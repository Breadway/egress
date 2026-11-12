package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	probeTimeout   = 5 * time.Second
	probeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
	maxProbeIPs    = 4
)

// errIgnoredName marks a special-use name that is never probed or routed.
var errIgnoredName = errors.New("ignored special-use name")

// ProbeOptions controls one direct probe. TunnelStatus is only called when the
// direct answer is a 403 or 451, to tell a site policy from a network block; it
// should fetch the same URL through the tunnel.
type ProbeOptions struct {
	Interface    string
	Timeout      time.Duration
	UserAgent    string
	Resolve      func(context.Context, string) ([]net.IP, error)
	TunnelStatus func(context.Context, string) (int, error)
}

// ProbeResult is the definitive classification of one direct probe.
type ProbeResult struct {
	Domain   string
	IPs      []string
	IP       string
	Status   int
	Evidence Evidence
	State    DomainState
	// Weak marks a connect timeout. It is a hint, not proof: a host in a
	// rotating DNS pool can have one dead address while others work, so a
	// single weak result must not be enough to block.
	Weak bool
	// Confirmed marks two independent weak samples, which is enough to block.
	Confirmed bool
	Transient bool
	Latency   time.Duration
	Err       error
}

// ProbeConfirmed probes once, and when the result is a weak connect timeout it
// takes a second independent sample with a fresh DNS answer. A rotating pool
// often answers with a working address the second time; a filtered network
// times out both times.
func ProbeConfirmed(ctx context.Context, domain string, opts ProbeOptions) ProbeResult {
	first := ProbeDomain(ctx, domain, opts)
	if !first.Weak {
		return first
	}
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return first
	}
	second := ProbeDomain(ctx, domain, opts)
	combined := combineProbeSamples(first, second)
	combined.Confirmed = true
	return combined
}

// combineProbeSamples prefers a working sample, then a definitive block, then
// a weak timeout.
func combineProbeSamples(samples ...ProbeResult) ProbeResult {
	for _, r := range samples {
		if r.State == StateAllowed {
			return r
		}
	}
	for _, r := range samples {
		if r.State == StateBlocked {
			return r
		}
	}
	for _, r := range samples {
		if r.Weak {
			return r
		}
	}
	if len(samples) > 0 {
		return samples[len(samples)-1]
	}
	return ProbeResult{Transient: true}
}

func (r ProbeResult) String() string {
	state := string(r.State)
	if r.Transient {
		state = "transient"
	}
	status := "-"
	if r.Status > 0 {
		status = strconv.Itoa(r.Status)
	}
	detail := ""
	if r.Evidence != EvidenceNone {
		detail = " evidence=" + string(r.Evidence)
	}
	if r.Err != nil {
		detail += " err=" + r.Err.Error()
	}
	return fmt.Sprintf("%s state=%s status=%s ip=%s ms=%d%s",
		r.Domain, state, status, r.IP, r.Latency.Milliseconds(), detail)
}

// ProbeDomain tests one domain over the direct path. It never goes through the
// tunnel unless TunnelStatus does, and it returns transient for anything that
// is not clearly a filter.
func ProbeDomain(ctx context.Context, domain string, opts ProbeOptions) ProbeResult {
	res := ProbeResult{Domain: NormalizeDomain(domain)}
	if res.Domain == "" {
		res.Transient = true
		res.Err = errors.New("empty domain")
		return res
	}
	if probeIgnoredName(res.Domain) {
		res.Transient = true
		res.Err = errIgnoredName
		return res
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = probeTimeout
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = probeUserAgent
	}
	resolve := opts.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, name string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", name)
		}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	ips, err := resolve(lookupCtx, res.Domain)
	cancel()
	if err != nil || len(ips) == 0 {
		res.Transient = true
		res.Err = fmt.Errorf("resolve: %w", err)
		return res
	}
	// IPv4 first, then IPv6. A working AAAA answer is enough to prove the
	// name is reachable even when one A record is dead.
	sort.SliceStable(ips, func(i, j int) bool {
		return ips[i].To4() != nil && ips[j].To4() == nil
	})
	if len(ips) > maxProbeIPs {
		ips = ips[:maxProbeIPs]
	}
	for _, ip := range ips {
		res.IPs = append(res.IPs, ip.String())
	}

	var blocked, weak *ProbeResult
	for _, ip := range ips {
		one := probeIP(ctx, res.Domain, ip.String(), timeout, ua, opts)
		if one.State == StateAllowed {
			return one
		}
		if one.State == StateBlocked && blocked == nil {
			b := one
			blocked = &b
		}
		if one.Weak && weak == nil {
			w := one
			weak = &w
		}
		if res.Err == nil {
			res.Err = one.Err
		}
	}
	if blocked != nil {
		return *blocked
	}
	if weak != nil {
		return *weak
	}
	res.Transient = true
	if res.Err == nil {
		res.Err = errors.New("no address reached")
	}
	return res
}

func probeIP(ctx context.Context, domain, ip string, timeout time.Duration, ua string, opts ProbeOptions) ProbeResult {
	res := ProbeResult{Domain: domain, IP: ip, Transient: true}
	dialer := &net.Dialer{Timeout: timeout, Control: deviceControl(opts.Interface)}

	start := time.Now()
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		res.Latency = time.Since(start)
		res.Err = err
		res.State, res.Evidence = classifyDialError(err)
		res.Weak = res.Evidence == EvidenceConnectStall
		res.Transient = res.State == StateUnknown && !res.Weak
		return res
	}
	defer raw.Close()

	tconn := tls.Client(raw, &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12})
	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	err = tconn.HandshakeContext(handshakeCtx)
	cancel()
	res.Latency = time.Since(start)
	if err != nil {
		res.Err = err
		res.State, res.Evidence = classifyTLSError(err)
		res.Transient = res.State != StateBlocked
		return res
	}
	defer tconn.Close()

	status, err := headStatus(tconn, domain, ua, timeout)
	if err != nil {
		res.Err = err
		if isTimeout(err) {
			res.State, res.Evidence = StateBlocked, EvidenceTLSStall
			res.Transient = false
		}
		return res
	}
	res.Status = status

	switch {
	case status == 403 || status == 451:
		if opts.TunnelStatus == nil {
			res.Err = fmt.Errorf("HTTP %d without a tunnel comparison", status)
			return res
		}
		compareCtx, cancel := context.WithTimeout(ctx, 2*timeout)
		tunnelStatus, terr := opts.TunnelStatus(compareCtx, domain)
		cancel()
		if terr != nil {
			res.Err = terr
			return res
		}
		if tunnelStatus > 0 && tunnelStatus < 400 {
			res.State, res.Evidence = StateBlocked, EvidenceIPRejected
			res.Transient = false
			return res
		}
		res.Transient = true
		return res
	case status >= 500:
		res.Err = fmt.Errorf("HTTP %d", status)
		return res
	default:
		res.State = StateAllowed
		res.Transient = false
		return res
	}
}

// headStatus sends a minimal HEAD request and returns the status code.
func headStatus(conn net.Conn, domain, ua string, timeout time.Duration) (int, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	req := "HEAD / HTTP/1.1\r\nHost: " + domain + "\r\nUser-Agent: " + ua +
		"\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return 0, err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, fmt.Errorf("bad status line %q", line)
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("bad status line %q", line)
	}
	return status, nil
}

// classifyDialError turns a TCP connect error into a verdict. A timeout is the
// school blackholing the flow; a refusal is transient.
func classifyDialError(err error) (DomainState, Evidence) {
	if err == nil {
		return StateUnknown, EvidenceNone
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateUnknown, EvidenceNone
	}
	if isTimeout(err) {
		// A connect timeout is weak evidence: a dead address in a rotating
		// pool looks the same as a filter. The profile needs two of these
		// before it blocks.
		return StateUnknown, EvidenceConnectStall
	}
	return StateUnknown, EvidenceNone
}

// probeIgnoredName reports special-use and non-routable names that must never
// be probed or routed. A DNS-only name such as ipv4only.arpa has no HTTPS
// service, and probing it would mark it blocked forever.
func probeIgnoredName(domain string) bool {
	domain = NormalizeDomain(domain)
	if domain == "" || !strings.Contains(domain, ".") {
		return true
	}
	for _, suffix := range []string{".arpa", ".local", ".localhost", ".invalid", ".test", ".onion", ".home", ".lan"} {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

// recordProbeOutcome applies a probe to the profile. A definitive block counts
// as a full failure streak; a weak connect timeout counts as one failure, so
// two independent timeouts are needed. It returns whether the profile changed.
func recordProbeOutcome(p *Profile, domain string, res ProbeResult, now time.Time) bool {
	switch res.State {
	case StateBlocked:
		p.RecordProbe(domain, res.Evidence, true, now)
		p.RecordProbe(domain, res.Evidence, true, now)
		return true
	case StateAllowed:
		p.RecordProbe(domain, EvidenceNone, false, now)
		return true
	case StateUnknown:
		if res.Weak {
			p.RecordProbe(domain, res.Evidence, true, now)
			if res.Confirmed {
				p.RecordProbe(domain, res.Evidence, true, now)
			}
			return true
		}
	}
	return false
}

// classifyTLSError turns a handshake error into a verdict. A certificate
// substitution or a timeout/reset after the TCP connect is the filter.
func classifyTLSError(err error) (DomainState, Evidence) {
	if err == nil {
		return StateUnknown, EvidenceNone
	}
	if isCertError(err) {
		return StateBlocked, EvidenceCertSubstitution
	}
	if isTimeout(err) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.ErrUnexpectedEOF) {
		return StateBlocked, EvidenceTLSStall
	}
	return StateUnknown, EvidenceNone
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isCertError(err error) bool {
	var verify *tls.CertificateVerificationError
	if errors.As(err, &verify) {
		return true
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return true
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return true
	}
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid)
}
