package split

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"egress/internal/core"
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
	ProbeTimeout   = 5 * time.Second
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
	// Title is the document title of the direct response, used to recognise a
	// block page whose wording differs but whose title does not.
	Title string
	Err   error
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
	res := ProbeResult{Domain: core.NormalizeDomain(domain)}
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
		timeout = ProbeTimeout
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

const (
	// probeBlockBytes covers an appliance block page. A 200-status block page
	// can carry tens of kilobytes of inline CSS ahead of its title, so every
	// response is read this far, not only a refusal.
	probeBlockBytes = 64 << 10
)

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

	status, body, location, err := headFetch(tconn, domain, ua, timeout)
	if err != nil {
		res.Err = err
		if isTimeout(err) {
			res.State, res.Evidence = StateBlocked, EvidenceTLSStall
			res.Transient = false
		}
		return res
	}
	res.Status = status
	res.Title = htmlTitle(body)
	if sig := blockPageSignature(status, res.Title, body, location); sig != "" {
		res.State, res.Evidence = StateBlocked, Evidence(string(EvidenceInterceptPage)+":"+sig)
		res.Transient = false
		return res
	}

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

// headFetch sends a GET and returns the status plus the first few kilobytes of
// the body. A HEAD would be cheaper, but a filter that intercepts TLS answers
// 200 with its own block page, and only the body distinguishes that from the
// real site.
func headFetch(conn net.Conn, domain, ua string, timeout time.Duration) (int, string, string, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, "", "", err
	}
	req := "GET / HTTP/1.1\r\nHost: " + domain + "\r\nUser-Agent: " + ua +
		"\r\nAccept: text/html,*/*\r\nRange: bytes=0-65535\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return 0, "", "", err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, "", "", err
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, "", "", fmt.Errorf("bad status line %q", line)
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, "", "", fmt.Errorf("bad status line %q", line)
	}
	location := ""
	for {
		header, herr := br.ReadString('\n')
		if herr != nil || header == "\r\n" || header == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(header), "location:") {
			location = strings.TrimSpace(header[len("location:"):])
		}
	}
	// Read the same amount for every status. A block page served with 200 can
	// put tens of kilobytes of inline CSS before its title, and a 302 can carry
	// the appliance's block-page URL only in Location.
	limit := probeBlockBytes
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for len(body) < limit {
		n, rerr := br.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	return status, string(body), location, nil
}

// Block pages are identified by structure, not prose. A school appliance can
// localise its wording, but the links it generates and the titles it uses stay
// the same. These signatures come from a real FortiGate page captured on an
// intercepting network: title "Web Filter Violation", heading "FortiGuard
// Intrusion Prevention - Access Blocked", a rating link to
// globalurl.fortinet.net, and a 403 over a trusted enterprise CA.
//
// A vendor name alone is not enough: a security site's front page can discuss
// FortiGuard. A signature therefore needs a block-page-only URL, a block-page
// title, or a refusal status together with the vendor name.
var blockPageURLs = []struct{ name, marker string }{
	{"fortigate", "fortinet.net/rate/submit"},
	{"fortigate", "blocked.fortinet.com"},
	{"cisco-umbrella", "policy.cisco.com"},
}

var blockPageTitles = []struct{ name, marker string }{
	{"fortigate", "web filter violation"},
	{"fortigate", "web page blocked"},
	{"fortigate", "intrusion prevention"},
	{"cisco-umbrella", "blocked by umbrella"},
}

var blockPageVendors = []struct{ name, marker string }{
	{"fortigate", "fortiguard"},
	{"fortigate", "fortinet"},
	{"bluecoat", "bluecoat"},
	{"sonicwall", "sonicwall"},
	{"untangle", "untangle"},
	{"palo-alto", "palo alto networks"},
}

// blockPageSignature names the appliance whose block page this is, or "" when
// the response does not look like one. The name is recorded as evidence, so a
// report says which filter produced the page.
func blockPageSignature(status int, title, body, location string) string {
	// A filter often answers with a redirect to its block page. The target is
	// the only place the appliance names itself, so inspect it before the body
	// and do not treat the redirect as allowed.
	if location != "" {
		loc := strings.ToLower(location)
		for _, sig := range blockPageURLs {
			if strings.Contains(loc, sig.marker) {
				return sig.name
			}
		}
	}
	lower := strings.ToLower(body)
	for _, sig := range blockPageURLs {
		if strings.Contains(lower, sig.marker) {
			return sig.name
		}
	}
	titleLower := normalizeTitle(title)
	for _, sig := range blockPageTitles {
		if strings.Contains(titleLower, sig.marker) {
			return sig.name
		}
	}
	if status >= 400 {
		for _, sig := range blockPageVendors {
			if strings.Contains(lower, sig.marker) {
				return sig.name
			}
		}
	}
	return ""
}

func normalizeTitle(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// htmlTitle returns the document title, trimmed.
func htmlTitle(body string) string {
	lower := strings.ToLower(body)
	open := strings.Index(lower, "<title")
	if open < 0 {
		return ""
	}
	gt := strings.Index(lower[open:], ">")
	if gt < 0 {
		return ""
	}
	start := open + gt + 1
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return ""
	}
	return strings.Join(strings.Fields(body[start:start+end]), " ")
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
	domain = core.NormalizeDomain(domain)
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

// Proxy is the per-user Windows split client: an HTTP CONNECT proxy that
// decides per destination whether to go direct or through the Aegis relay. It
// also serves the PAC file the browser points at.
//
// Unknown destinations are probed once; the result is stored in the same
// per-network profile the Linux split mode uses, so both paths learn the same
// way.
type Proxy struct {
	dir        string
	listenAddr string
	relayAddr  string
	user       string
	pass       string
	network    string
	log        *log.Logger

	mu        sync.Mutex
	profile   *Profile
	path      string
	overrides Overrides

	probe     func(context.Context, string, ProbeOptions) ProbeResult
	dial      func(context.Context, string, string) (net.Conn, error)
	socksDial func(context.Context, string, string, string, string) (net.Conn, error)

	direct  atomic.Int64
	relayed atomic.Int64

	// tunnelUp reports whether the WireGuard relay tunnel is running. It is
	// injected because this process may not be the one that manages it. When
	// it is up, a blocked destination dialled directly is carried by the
	// tunnel, so the SOCKS relay must not be used: the whole point of the
	// tunnel is that the interceptor sees ciphertext.
	tunnelUp func() bool
}

func NewProxy(network, dir, listen, relay, user, pass string, logger *log.Logger) *Proxy {
	p := &Proxy{
		listenAddr: listen,
		relayAddr:  relay,
		user:       user,
		pass:       pass,
		network:    network,
		log:        logger,
	}
	p.dir = dir
	p.path = ProfilePathIn(dir, network)
	p.overrides = LoadOverrides(dir)
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

// SetTunnelUp tells the proxy how to ask whether the relay tunnel is running.
func (p *Proxy) SetTunnelUp(fn func() bool) { p.tunnelUp = fn }

func (p *Proxy) tunnelReady() bool {
	return p.tunnelUp != nil && p.tunnelUp()
}

// ListenAddr is where the proxy accepts CONNECT and serves the PAC.
func (p *Proxy) ListenAddr() string { return p.listenAddr }

// Stats counts the profile's decisions: blocked, contested among them, and
// explicitly allowed. The tray and diagnose show these so a filter can be
// understood without opening a file.
func (p *Proxy) Stats() (blocked, contested, allowed int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, entry := range p.profile.Entries {
		switch entry.State {
		case StateBlocked:
			blocked++
			if entry.Contested {
				contested++
			}
		case StateAllowed:
			allowed++
		}
	}
	return blocked, contested, allowed
}

// ProtocolStates is a copy of the network's outbound protocol picture.
func (p *Proxy) ProtocolStates() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.profile.Protocols))
	for k, v := range p.profile.Protocols {
		out[k] = v
	}
	return out
}

// ReloadOverrides re-reads split-allow.txt and split-block.txt so an edit takes
// effect from the tray without restarting the proxy.
func (p *Proxy) ReloadOverrides() {
	next := LoadOverrides(p.dir)
	p.mu.Lock()
	p.overrides = next
	p.mu.Unlock()
}

// TopDomains lists blocked domains, contested first, for the tray submenu.
func (p *Proxy) TopDomains(limit int) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	type item struct {
		name      string
		contested bool
	}
	var items []item
	for name, entry := range p.profile.Entries {
		if entry.State == StateBlocked {
			items = append(items, item{name, entry.Contested})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].contested != items[j].contested {
			return items[i].contested
		}
		return items[i].name < items[j].name
	})
	out := make([]string, 0, limit)
	for _, it := range items {
		if len(out) >= limit {
			break
		}
		out = append(out, it.name)
	}
	return out
}

// noteRelayFallback records that a blocked domain worked directly, so a dead
// relay does not keep costing the user that site.
func (p *Proxy) noteRelayFallback(host string) {
	host = core.NormalizeDomain(host)
	now := time.Now()
	p.mu.Lock()
	if _, ok := p.profile.Entries[host]; ok {
		p.profile.AddAllowed(host, EvidenceFeed, now)
		if err := p.profile.Save(p.path); err != nil {
			p.log.Printf("proxy: save profile: %v", err)
		}
	}
	p.mu.Unlock()
}

// Network is the local profile key, for display.
func (p *Proxy) Network() string { return p.network }

func (p *Proxy) handler() http.Handler {
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

func (p *Proxy) Serve(ctx context.Context) error {
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

func PacScript(listen string) string {
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  // Windows' own connectivity probe goes direct. Sending it through the
  // proxy makes Windows report "no internet" whenever the proxy path is slow
  // or the relay is down, even though ordinary traffic would work.
  if (host == "www.msftconnecttest.com" || host == "www.msftncsi.com" ||
      dnsDomainIs(host, ".msftncsi.com")) {
    return "DIRECT";
  }
  // Everything else goes to the local proxy, which decides per destination
  // whether to go direct or through the Aegis relay.
  return "PROXY %s; DIRECT";
}
`, listen)
}

func (p *Proxy) servePAC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, PacScript(p.listenAddr))
}

// serveHTTP forwards a plain http request. A browser configured for a proxy
// sends these as absolute URLs rather than a CONNECT tunnel, and Windows'
// connectivity probe is one of them, so dropping them reports the machine as
// offline even though https still works (EGRESS-99).
func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	mode := p.decide(ctx, r.URL.Hostname())
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if mode == StateBlocked && p.tunnelReady() {
				// The tunnel holds a route for this destination, so a direct
				// dial is the encrypted path.
				if conn, err := p.dial(ctx, network, addr); err == nil {
					p.relayed.Add(1)
					return conn, nil
				}
				p.log.Printf("proxy: tunnel dial failed for %s; falling back to the relay", addr)
			}
			if mode == StateBlocked {
				if conn, err := p.socksDial(ctx, p.relayAddr, p.user, p.pass, addr); err == nil {
					return conn, nil
				}
				p.log.Printf("proxy: relay failed for %s; trying direct", addr)
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
		log.Printf("proxy: %s (%s): %v", r.URL.Host, mode, err)
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
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
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
	if mode == StateBlocked && p.tunnelReady() {
		// Routed into the tunnel: dial directly and let WireGuard carry it.
		upstream, err = p.dial(ctx, "tcp", r.Host)
		if err == nil {
			p.relayed.Add(1)
		} else {
			p.log.Printf("proxy: tunnel dial failed for %s (%v); falling back to the relay", r.Host, err)
		}
	}
	if upstream == nil && mode == StateBlocked {
		upstream, err = p.socksDial(ctx, p.relayAddr, p.user, p.pass, r.Host)
		if err != nil {
			// A dead relay must not take a working site down. Try the direct
			// path and remember that the block did not hold this time.
			p.log.Printf("proxy: relay failed for %s (%v); trying direct", r.Host, err)
			upstream, err = p.dial(ctx, "tcp", r.Host)
			if err == nil {
				p.direct.Add(1)
				p.noteRelayFallback(r.Host)
			}
		} else {
			p.relayed.Add(1)
		}
	} else {
		upstream, err = p.dial(ctx, "tcp", r.Host)
		p.direct.Add(1)
	}
	if err != nil {
		log.Printf("proxy: %s (%s): %v", r.Host, mode, err)
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
func (p *Proxy) decide(ctx context.Context, host string) DomainState {
	host = core.NormalizeDomain(host)
	if state, ok := p.overrides.Forced(host); ok {
		return state
	}
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
func (p *Proxy) probeWithConfirm(ctx context.Context, host string) ProbeResult {
	first := p.probe(ctx, host, ProbeOptions{Timeout: ProbeTimeout})
	if !first.Weak {
		return first
	}
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return first
	}
	second := p.probe(ctx, host, ProbeOptions{Timeout: ProbeTimeout})
	combined := combineProbeSamples(first, second)
	combined.Confirmed = true
	return combined
}

func (p *Proxy) stats() (direct, relayed int64) {
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
