package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// splitProxy is the per-user Windows split client: an HTTP CONNECT proxy that
// decides per destination whether to go direct or through the Aegis relay. It
// also serves the PAC file the browser points at.
//
// Unknown destinations are probed once; the result is stored in the same
// per-network profile the Linux split mode uses, so both paths learn the same
// way.
type splitProxy struct {
	listenAddr string
	relayAddr  string
	user       string
	pass       string
	network    string
	log        *log.Logger

	mu      sync.Mutex
	profile *Profile
	path    string

	probe     func(context.Context, string, ProbeOptions) ProbeResult
	dial      func(context.Context, string, string) (net.Conn, error)
	socksDial func(context.Context, string, string, string, string) (net.Conn, error)

	direct  atomic.Int64
	relayed atomic.Int64
}

func newSplitProxy(network, dir, listen, relay, user, pass string, logger *log.Logger) *splitProxy {
	p := &splitProxy{
		listenAddr: listen,
		relayAddr:  relay,
		user:       user,
		pass:       pass,
		network:    network,
		log:        logger,
	}
	p.path = ProfilePathIn(dir, network)
	profile, err := LoadProfile(p.path, network)
	if err != nil {
		logger.Printf("proxy: could not read %s (%v); starting empty", p.path, err)
		profile = NewProfile(network)
	}
	p.profile = profile
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	p.dial = dialer.DialContext
	p.probe = ProbeDomain
	p.socksDial = socksConnect
	return p
}

func (p *splitProxy) handler() http.Handler {
	// CONNECT requests use authority-form URLs, so a ServeMux would 404 them.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodConnect:
			p.serveConnect(w, r)
		case r.URL.Path == "/proxy.pac":
			p.servePAC(w, r)
		case r.URL.IsAbs() && r.URL.Scheme == "http":
			p.serveHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (p *splitProxy) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              p.listenAddr,
		Handler:           p.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func pacScript(listen string) string {
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  // Every request goes to the local proxy, which decides per destination
  // whether to go direct or through the Aegis relay.
  return "PROXY %s; DIRECT";
}
`, listen)
}

func (p *splitProxy) servePAC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, pacScript(p.listenAddr))
}

// serveHTTP forwards a plain http request. A browser configured for a proxy
// sends these as absolute URLs rather than a CONNECT tunnel, and Windows'
// connectivity probe is one of them, so dropping them reports the machine as
// offline even though https still works (EGRESS-99).
func (p *splitProxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	mode := p.decide(ctx, r.URL.Hostname())
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if mode == StateBlocked {
				return p.socksDial(ctx, p.relayAddr, p.user, p.pass, addr)
			}
			return p.dial(ctx, network, addr)
		},
	}
	defer transport.CloseIdleConnections()

	out := r.Clone(ctx)
	out.RequestURI = ""
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")
	resp, err := transport.RoundTrip(out)
	if err != nil {
		debugf("proxy: %s (%s): %v", r.URL.Host, mode, err)
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// serveConnect tunnels https and other protocols after a CONNECT request.
func (p *splitProxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "this proxy only supports CONNECT", http.StatusMethodNotAllowed)
		return
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	mode := p.decide(ctx, host)
	var upstream net.Conn
	if mode == StateBlocked {
		upstream, err = p.socksDial(ctx, p.relayAddr, p.user, p.pass, r.Host)
		p.relayed.Add(1)
	} else {
		upstream, err = p.dial(ctx, "tcp", r.Host)
		p.direct.Add(1)
	}
	if err != nil {
		debugf("proxy: %s (%s): %v", r.Host, mode, err)
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	// Bytes the client sent after CONNECT are already buffered.
	if n := buf.Reader.Buffered(); n > 0 {
		if _, err := io.CopyN(upstream, buf, int64(n)); err != nil {
			client.Close()
			upstream.Close()
			return
		}
	}
	pipeConns(client, upstream)
}

// decide returns the state for one destination, probing unknown names once and
// recording the result.
func (p *splitProxy) decide(ctx context.Context, host string) DomainState {
	host = NormalizeDomain(host)
	now := time.Now()
	p.mu.Lock()
	state := p.profile.State(host, now)
	p.mu.Unlock()
	if state != StateUnknown {
		return state
	}

	probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	res := p.probeWithConfirm(probeCtx, host)
	cancel()

	p.mu.Lock()
	if recordProbeOutcome(p.profile, host, res, now) {
		if err := p.profile.Save(p.path); err != nil {
			p.log.Printf("proxy: save profile: %v", err)
		}
	}
	p.mu.Unlock()

	if res.State == StateBlocked {
		return StateBlocked
	}
	return StateAllowed
}

// probeWithConfirm takes a second sample after a weak connect timeout, using
// the injectable probe so tests can stay offline.
func (p *splitProxy) probeWithConfirm(ctx context.Context, host string) ProbeResult {
	first := p.probe(ctx, host, ProbeOptions{Timeout: probeTimeout})
	if !first.Weak {
		return first
	}
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return first
	}
	second := p.probe(ctx, host, ProbeOptions{Timeout: probeTimeout})
	combined := combineProbeSamples(first, second)
	combined.Confirmed = true
	return combined
}

func (p *splitProxy) stats() (direct, relayed int64) {
	return p.direct.Load(), p.relayed.Load()
}

// pipeConns copies both directions and half-closes as each side finishes.
func pipeConns(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(b, a)
		if tcp, ok := b.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(a, b)
	if tcp, ok := a.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-done
}
