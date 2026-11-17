package split

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"egress/internal/core"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProfileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "split-test.json")
	now := time.Now()

	p := NewProfile("NCC|10.179.160.1")
	p.RecordProbe("discord.com", EvidenceTLSStall, true, now)
	p.RecordProbe("discord.com", EvidenceTLSStall, true, now)
	p.RecordProbe("github.com", EvidenceNone, false, now)
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}

	got, err := LoadProfile(path, "NCC|10.179.160.1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State("discord.com", now) != StateBlocked {
		t.Errorf("discord should be blocked, got %s", got.State("discord.com", now))
	}
	if got.State("github.com", now) != StateAllowed {
		t.Errorf("github should be allowed, got %s", got.State("github.com", now))
	}
	if got.Entries["discord.com"].Evidence != EvidenceTLSStall {
		t.Errorf("evidence not stored: %q", got.Entries["discord.com"].Evidence)
	}
}

func TestProfileRequiresTwoFailures(t *testing.T) {
	now := time.Now()
	p := NewProfile("net")
	p.RecordProbe("discord.com", EvidenceTLSStall, true, now)
	if p.State("discord.com", now) == StateBlocked {
		t.Fatal("one failure must not block")
	}
	p.RecordProbe("discord.com", EvidenceTLSStall, true, now)
	if p.State("discord.com", now) != StateBlocked {
		t.Fatal("two failures must block")
	}
	// A success clears the streak and the blocked state.
	p.RecordProbe("discord.com", EvidenceNone, false, now)
	if p.State("discord.com", now) != StateAllowed {
		t.Fatal("success must clear blocked")
	}
}

func TestAllowedExpires(t *testing.T) {
	now := time.Now()
	p := NewProfile("net")
	p.RecordProbe("github.com", EvidenceNone, false, now)
	if p.State("github.com", now.Add(allowedTTL-time.Minute)) != StateAllowed {
		t.Fatal("allowed should hold inside the TTL")
	}
	if p.State("github.com", now.Add(allowedTTL+time.Minute)) != StateUnknown {
		t.Fatal("allowed should expire")
	}
}

func TestAddBlocked(t *testing.T) {
	now := time.Now()
	p := NewProfile("net")
	p.AddBlocked("discord.com", EvidenceSeed, now)
	if p.State("discord.com", now) != StateBlocked {
		t.Fatal("seed entry must be blocked")
	}
	if len(p.BlockedDomains(now)) != 1 {
		t.Fatal("blocked list should have one entry")
	}
}

func TestNetworkKeyAndPath(t *testing.T) {
	if got := NetworkKey("NCC", "10.179.160.1"); got != "NCC|10.179.160.1" {
		t.Errorf("network key: %q", got)
	}
	path := ProfilePath("NCC 4|10.179.160.1")
	if filepath.Base(path) != "split-NCC_4_10.179.160.1.json" {
		t.Errorf("profile path: %q", path)
	}
}

func TestClassifyProbeErrors(t *testing.T) {
	dial := []struct {
		name string
		err  error
		want DomainState
		ev   Evidence
	}{
		{"timeout", os.ErrDeadlineExceeded, StateUnknown, EvidenceConnectStall},
		{"refused", syscall.ECONNREFUSED, StateUnknown, EvidenceNone},
		{"other", errors.New("boom"), StateUnknown, EvidenceNone},
	}
	for _, tc := range dial {
		got, ev := classifyDialError(tc.err)
		if got != tc.want || ev != tc.ev {
			t.Errorf("dial %s: got (%s,%s), want (%s,%s)", tc.name, got, ev, tc.want, tc.ev)
		}
	}
	handshake := []struct {
		name string
		err  error
		want DomainState
		ev   Evidence
	}{
		{"cert", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, StateBlocked, EvidenceCertSubstitution},
		{"reset", syscall.ECONNRESET, StateBlocked, EvidenceTLSStall},
		{"deadline", os.ErrDeadlineExceeded, StateBlocked, EvidenceTLSStall},
		{"other", errors.New("boom"), StateUnknown, EvidenceNone},
	}
	for _, tc := range handshake {
		got, ev := classifyTLSError(tc.err)
		if got != tc.want || ev != tc.ev {
			t.Errorf("tls %s: got (%s,%s), want (%s,%s)", tc.name, got, ev, tc.want, tc.ev)
		}
	}
}

func TestProbeIgnoredName(t *testing.T) {
	ignored := []string{"ipv4only.arpa", "router.local", "printer", "example.test", "x.onion", "nas.lan", ""}
	for _, name := range ignored {
		if !probeIgnoredName(name) {
			t.Errorf("%q should be ignored", name)
		}
	}
	allowed := []string{"discord.com", "store.steampowered.com", "example.com"}
	for _, name := range allowed {
		if probeIgnoredName(name) {
			t.Errorf("%q should be probed", name)
		}
	}
}

func TestRecordProbeOutcome(t *testing.T) {
	now := time.Now()
	p := NewProfile("net")
	weak := ProbeResult{Domain: "unknown.example.org", State: StateUnknown, Evidence: EvidenceConnectStall, Weak: true}
	if !recordProbeOutcome(p, "unknown.example.org", weak, now) {
		t.Fatal("weak result should record a failure")
	}
	if p.State("unknown.example.org", now) == StateBlocked {
		t.Fatal("one weak timeout must not block an unknown name")
	}
	recordProbeOutcome(p, "unknown.example.org", weak, now)
	if p.State("unknown.example.org", now) != StateBlocked {
		t.Fatal("two weak timeouts should block")
	}
	// Two samples confirmed by ProbeConfirmed block in one go.
	confirmed := ProbeResult{Domain: "discord.com", State: StateUnknown, Evidence: EvidenceConnectStall, Weak: true, Confirmed: true}
	recordProbeOutcome(p, "discord.com", confirmed, now)
	if p.State("discord.com", now) != StateBlocked {
		t.Fatal("two confirmed timeouts should block")
	}
	definitive := ProbeResult{Domain: "steamcommunity.com", State: StateBlocked, Evidence: EvidenceTLSStall}
	recordProbeOutcome(p, "steamcommunity.com", definitive, now)
	if p.State("steamcommunity.com", now) != StateBlocked {
		t.Fatal("a definitive block should apply immediately")
	}
	allowed := ProbeResult{Domain: "steamcommunity.com", State: StateAllowed}
	recordProbeOutcome(p, "steamcommunity.com", allowed, now)
	if p.State("steamcommunity.com", now) != StateAllowed {
		t.Fatal("a success should clear the block")
	}
}

func TestCombineProbeSamples(t *testing.T) {
	allowed := ProbeResult{State: StateAllowed}
	blocked := ProbeResult{State: StateBlocked, Evidence: EvidenceTLSStall}
	weak := ProbeResult{State: StateUnknown, Evidence: EvidenceConnectStall, Weak: true}
	transient := ProbeResult{State: StateUnknown, Transient: true}

	if got := combineProbeSamples(weak, allowed); got.State != StateAllowed {
		t.Errorf("a working sample must win: %+v", got)
	}
	if got := combineProbeSamples(weak, blocked); got.State != StateBlocked {
		t.Errorf("a definitive block must beat weak: %+v", got)
	}
	if got := combineProbeSamples(weak, weak); !got.Weak || got.State != StateUnknown {
		t.Errorf("two weak samples stay weak: %+v", got)
	}
	if got := combineProbeSamples(transient, transient); got.State != StateUnknown || got.Weak {
		t.Errorf("transient samples stay transient: %+v", got)
	}
}

func TestHeadStatus(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
	}()
	status, err := headStatus(client, "example.com", "test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if status != 403 {
		t.Errorf("status %d, want 403", status)
	}
}

func TestProbeResolveFailureIsTransient(t *testing.T) {
	res := ProbeDomain(context.Background(), "example.invalid", ProbeOptions{
		Resolve: func(ctx context.Context, name string) ([]net.IP, error) {
			return nil, errors.New("no such host")
		},
	})
	if !res.Transient || res.State == StateBlocked {
		t.Errorf("resolve failure must be transient, got %+v", res)
	}
}

// buildAnswer builds a minimal A response for example.com with two A records
// and a CNAME before them, to exercise name skipping.
func buildAnswer() []byte {
	var b []byte
	b = append(b, 0x12, 0x34, 0x81, 0x80) // id, flags
	b = append(b, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00)
	// question: example.com A IN
	b = append(b, 7)
	b = append(b, []byte("example")...)
	b = append(b, 3)
	b = append(b, []byte("com")...)
	b = append(b, 0, 0, 1, 0, 1)
	// CNAME www.example.com
	b = append(b, 3)
	b = append(b, []byte("www")...)
	b = append(b, 0xc0, 0x0c)
	b = append(b, 0, 5, 0, 1, 0, 0, 0x01, 0x2c, 0, 6)
	b = append(b, 3)
	b = append(b, []byte("cdn")...)
	b = append(b, 0xc0, 0x0c)
	// A 93.184.216.34 ttl 300
	b = append(b, 0xc0, 0x2b) // pointer to www
	b = append(b, 0, 1, 0, 1, 0, 0, 0x01, 0x2c, 0, 4, 93, 184, 216, 34)
	return b
}

func TestDNSQueryName(t *testing.T) {
	query := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if got := core.DNSQueryName(query); got != "example.com" {
		t.Errorf("query name: %q", got)
	}
	if got := core.DNSQueryName(nil); got != "" {
		t.Errorf("nil query should be empty, got %q", got)
	}
}

func TestDNSAnswerIPv4(t *testing.T) {
	resp := buildAnswer()
	ips, ttl := core.DNSAnswerIPv4(resp)
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("ips: %v", ips)
	}
	if ttl != 300*time.Second {
		t.Errorf("ttl: %v", ttl)
	}
}

func TestRouteManagerAddCleanup(t *testing.T) {
	var calls [][]string
	rm := &RouteManager{
		dev:    "wg0",
		log:    log.New(testWriter{t}, "", 0),
		routes: map[string]time.Time{},
		run: func(args ...string) error {
			calls = append(calls, args)
			return nil
		},
	}
	now := time.Now()
	rm.Add([]net.IP{net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8)}, 0, now)
	if rm.Count() != 2 {
		t.Fatalf("count: %d", rm.Count())
	}
	if len(calls) != 2 || calls[0][0] != "replace" {
		t.Fatalf("calls: %v", calls)
	}
	rm.Cleanup(now.Add(routeMinTTL + time.Minute))
	if rm.Count() != 0 {
		t.Fatalf("routes survived cleanup: %d", rm.Count())
	}
}

func TestRouteManagerRemove(t *testing.T) {
	var calls [][]string
	rm := &RouteManager{
		dev:    "wg0",
		log:    log.New(testWriter{t}, "", 0),
		routes: map[string]time.Time{},
		run: func(args ...string) error {
			calls = append(calls, args)
			return nil
		},
	}
	now := time.Now()
	rm.Add([]net.IP{net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8)}, 0, now)
	rm.Remove([]string{"1.2.3.4", "9.9.9.9"})
	if rm.Count() != 1 {
		t.Fatalf("count after remove: %d", rm.Count())
	}
	found := false
	for _, call := range calls {
		if len(call) > 1 && call[0] == "del" && call[1] == "1.2.3.4" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no delete call: %v", calls)
	}
}

func TestSplitControllerRoutesBlockedDomain(t *testing.T) {
	var calls [][]string
	rm := &RouteManager{
		dev:    "wg0",
		log:    log.New(testWriter{t}, "", 0),
		routes: map[string]time.Time{},
		run: func(args ...string) error {
			calls = append(calls, args)
			return nil
		},
	}
	c := NewController("testnet", "wlan0", rm, log.New(testWriter{t}, "", 0))
	now := time.Now()
	c.profile = NewProfile("testnet")
	c.profile.AddBlocked("discord.com", EvidenceSeed, now)

	c.HandleAnswer("discord.com", []net.IP{net.IPv4(162, 159, 136, 232)}, 2*time.Minute)
	if rm.Count() != 1 {
		t.Fatalf("blocked answer did not route: %v", calls)
	}
	if len(calls) != 1 || calls[0][0] != "replace" {
		t.Fatalf("calls: %v", calls)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func TestMergeFeedDomains(t *testing.T) {
	now := time.Now()
	p := NewProfile("net")
	p.AddBlocked("poki.com", EvidenceIPRejected, now)

	added := mergeFeedDomains(p, []feedDomain{
		{Domain: "Discord.com", Evidence: "tls-stall", Count: 3},
		{Domain: "poki.com", Evidence: "ip-rejected"},
		{Domain: "not a domain", Evidence: "tls-stall"},
		{Domain: "ipv4only.arpa", Evidence: "connect-stall"},
	}, now)
	if added != 1 {
		t.Fatalf("added %d, want 1", added)
	}
	if p.State("discord.com", now) != StateBlocked {
		t.Fatal("feed domain not blocked")
	}
	if p.Entries["discord.com"].Evidence != EvidenceFeed {
		t.Fatalf("evidence: %q", p.Entries["discord.com"].Evidence)
	}
	if mergeFeedDomains(p, []feedDomain{{Domain: "discord.com"}}, now) != 0 {
		t.Fatal("merge must be idempotent")
	}
}

func TestDeviceIDAtStable(t *testing.T) {
	dir := t.TempDir()
	first := deviceIDAt(dir)
	if len(first) != 32 {
		t.Fatalf("id length %d", len(first))
	}
	if second := deviceIDAt(dir); second != first {
		t.Fatalf("id changed: %q then %q", first, second)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "device-id")); err != nil || len(data) == 0 {
		t.Fatalf("id file: %v", err)
	}
}

func TestPlausibleDomain(t *testing.T) {
	good := []string{"discord.com", "store.steampowered.com", "x.com"}
	for _, d := range good {
		if !plausibleDomain(d) {
			t.Errorf("%q should be plausible", d)
		}
	}
	bad := []string{"", "nodot", "has space.com", "http://x.com", "*.example.com"}
	for _, d := range bad {
		if plausibleDomain(d) {
			t.Errorf("%q should be rejected", d)
		}
	}
}

func TestReporterFlush(t *testing.T) {
	var got splitReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	r := newSplitReporter("net|10.0.0.1", t.TempDir(), log.New(testWriter{t}, "", 0))
	r.SetMergeFunc(func([]feedDomain, []feedProtocol) {})
	r.reportURL = srv.URL
	r.Report("discord.com", EvidenceTLSStall)
	r.Report("poki.com", EvidenceIPRejected)
	if err := r.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Device == "" || got.NetworkID != NetworkID("net|10.0.0.1") || len(got.Domains) != 2 {
		t.Fatalf("payload: %+v", got)
	}
	if r.pending() != 0 {
		t.Fatalf("queue not cleared: %d", r.pending())
	}
}

func TestReporterFeedFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("n") != NetworkID("net|10.0.0.1") {
			t.Errorf("network query: %q", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(feedResponse{Version: 1, Domains: []feedDomain{
			{Domain: "discord.com", Evidence: "tls-stall"},
		}})
	}))
	defer srv.Close()

	r := newSplitReporter("net|10.0.0.1", t.TempDir(), log.New(testWriter{t}, "", 0))
	r.seedURL = srv.URL
	var merged []feedDomain
	r.SetMergeFunc(func(domains []feedDomain, _ []feedProtocol) { merged = domains })
	r.fetchFeed(context.Background())
	if len(merged) != 1 || merged[0].Domain != "discord.com" {
		t.Fatalf("merged: %+v", merged)
	}
}

func TestPACScript(t *testing.T) {
	script := PacScript("127.0.0.1:1081")
	if !strings.Contains(script, "PROXY 127.0.0.1:1081; DIRECT") {
		t.Fatalf("pac: %s", script)
	}
}

func TestSocksConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var gotTarget string
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var greet [2]byte
		_, _ = io.ReadFull(br, greet[:])
		methods := make([]byte, greet[1])
		_, _ = io.ReadFull(br, methods)
		_, _ = conn.Write([]byte{5, 2})
		var authHead [2]byte
		_, _ = io.ReadFull(br, authHead[:])
		user := make([]byte, authHead[1])
		_, _ = io.ReadFull(br, user)
		var plen [1]byte
		_, _ = io.ReadFull(br, plen[:])
		pass := make([]byte, plen[0])
		_, _ = io.ReadFull(br, pass)
		if string(user) != "u" || string(pass) != "p" {
			_, _ = conn.Write([]byte{1, 1})
			return
		}
		_, _ = conn.Write([]byte{1, 0})
		var head [4]byte
		_, _ = io.ReadFull(br, head[:])
		l := make([]byte, 1)
		_, _ = io.ReadFull(br, l[:])
		name := make([]byte, l[0])
		_, _ = io.ReadFull(br, name)
		var port [2]byte
		_, _ = io.ReadFull(br, port[:])
		gotTarget = net.JoinHostPort(string(name), itoa(int(binary.BigEndian.Uint16(port[:]))))
		_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		_, _ = io.Copy(conn, br)
	}()

	conn, err := socksConnect(context.Background(), ln.Addr().String(), "u", "p", "discord.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if gotTarget != "discord.com:443" {
		t.Fatalf("target: %q", gotTarget)
	}
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("echo: %q %v", buf, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestProxyDecidesAndRecords(t *testing.T) {
	dir := t.TempDir()
	p := NewProxy("net", dir, "127.0.0.1:0", "127.0.0.1:1", "u", "p", log.New(testWriter{t}, "", 0))
	calls := 0
	p.probe = func(ctx context.Context, domain string, opts ProbeOptions) ProbeResult {
		calls++
		return ProbeResult{Domain: domain, State: StateBlocked, Evidence: EvidenceTLSStall}
	}
	if got := p.decide(context.Background(), "discord.com"); got != StateBlocked {
		t.Fatalf("state: %s", got)
	}
	if got := p.decide(context.Background(), "discord.com"); got != StateBlocked {
		t.Fatalf("second state: %s", got)
	}
	if calls != 1 {
		t.Fatalf("probe calls: %d (must be cached)", calls)
	}
	loaded, err := LoadProfile(ProfilePathIn(dir, "net"), "net")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State("discord.com", time.Now()) != StateBlocked {
		t.Fatal("profile not persisted")
	}
}

func TestProxyConnectDirect(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	p := NewProxy("net", t.TempDir(), "127.0.0.1:0", "127.0.0.1:1", "u", "p", log.New(testWriter{t}, "", 0))
	p.probe = func(ctx context.Context, domain string, opts ProbeOptions) ProbeResult {
		return ProbeResult{Domain: domain, State: StateAllowed}
	}
	srv := httptest.NewServer(p.handler())
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("CONNECT " + echo.Addr().String() + " HTTP/1.1\r\nHost: " + echo.Addr().String() + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("status: %q %v", line, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo: %q %v", buf, err)
	}
}

func TestProxyForwardsPlainHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + r.URL.Path))
	}))
	defer upstream.Close()

	p := NewProxy("net", t.TempDir(), "127.0.0.1:0", "127.0.0.1:1", "u", "p", log.New(testWriter{t}, "", 0))
	p.probe = func(ctx context.Context, domain string, opts ProbeOptions) ProbeResult {
		return ProbeResult{Domain: domain, State: StateAllowed}
	}
	proxy := httptest.NewServer(p.handler())
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	// This is the shape of Windows' connectivity probe: a plain http request
	// sent to the proxy as an absolute URL.
	resp, err := client.Get(upstream.URL + "/connecttest.txt")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d (plain http must be forwarded, not 404)", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello /connecttest.txt" {
		t.Fatalf("body: %q", body)
	}
}

func TestNetworkIDIsHashedAndStable(t *testing.T) {
	id := NetworkID("HomeNet|192.168.1.1")
	if len(id) != 32 {
		t.Fatalf("id %q", id)
	}
	if id != NetworkID("homenet|192.168.1.1") {
		t.Error("id is case-sensitive")
	}
	if id == NetworkID("OtherNet|192.168.1.1") {
		t.Error("different networks share an id")
	}
	if id == "HomeNet|192.168.1.1" {
		t.Error("id is not hashed")
	}
}

func TestMergeProtocolsKeepsLocalObservation(t *testing.T) {
	p := NewProfile("net")
	p.Protocols["udp"] = "ok" // measured locally
	changed := mergeProtocols(p, []feedProtocol{
		{Protocol: "udp", State: "blocked"}, // shared, must not override
		{Protocol: "tcp", State: "ok"},      // new, fills in
	})
	if p.Protocols["udp"] != "ok" {
		t.Errorf("local udp observation was overwritten: %q", p.Protocols["udp"])
	}
	if p.Protocols["tcp"] != "ok" {
		t.Errorf("shared tcp observation not merged: %q", p.Protocols["tcp"])
	}
	if changed != 1 {
		t.Errorf("changed = %d, want 1", changed)
	}
}

func TestProtocolsFlushWithoutDomains(t *testing.T) {
	var got splitReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	r := newSplitReporter("net", t.TempDir(), log.New(testWriter{t}, "", 0))
	r.reportURL = srv.URL
	r.SetProtocols([]splitProtocolReport{{Protocol: "udp", State: "blocked", Evidence: "no-reply"}})
	if err := r.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got.Protocols) != 1 || got.Protocols[0].Protocol != "udp" {
		t.Fatalf("protocols not sent: %+v", got)
	}
	// A second flush with nothing new must not resend them.
	got = splitReport{}
	if err := r.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got.Protocols) != 0 {
		t.Fatalf("protocols resent without a change: %+v", got)
	}
}

func TestOverridesBeatProbingAndFeed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "split-allow.txt"), []byte("# pinned direct\nok.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "split-block.txt"), []byte("bad.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o := LoadOverrides(dir)
	if state, ok := o.Forced("ok.example"); !ok || state != StateAllowed {
		t.Fatalf("allow override: %v %v", state, ok)
	}
	if state, ok := o.Forced("bad.example"); !ok || state != StateBlocked {
		t.Fatalf("block override: %v %v", state, ok)
	}
	if _, ok := o.Forced("other.example"); ok {
		t.Fatal("override applied to an unrelated domain")
	}
	if got := OverrideSummary(dir); len(got) != 2 {
		t.Fatalf("summary: %v", got)
	}
}

func TestNetworkAllowlist(t *testing.T) {
	dir := t.TempDir()
	if !NetworkAllowed(dir, "anything") {
		t.Fatal("missing allowlist should allow any network")
	}
	if err := SaveNetworks(dir, []string{"Home", "Office"}); err != nil {
		t.Fatal(err)
	}
	if !NetworkAllowed(dir, "home") {
		t.Error("listed ssid is case-insensitive")
	}
	if NetworkAllowed(dir, "Cafe") {
		t.Error("unlisted ssid allowed")
	}
	if !NetworkAllowed(dir, "") {
		t.Error("unreadable ssid should not block")
	}
	if got := LoadNetworks(dir); len(got) != 2 {
		t.Fatalf("load: %v", got)
	}
	if err := SaveNetworks(dir, nil); err != nil {
		t.Fatal(err)
	}
	if !NetworkAllowed(dir, "Cafe") {
		t.Error("cleared allowlist still blocks")
	}
}

func TestDefaultScanDomainsAreUsable(t *testing.T) {
	domains := DefaultScanDomains()
	if len(domains) < 100 {
		t.Fatalf("only %d domains; a seed list should cover the common services", len(domains))
	}
	seen := map[string]bool{}
	for _, d := range domains {
		d = core.NormalizeDomain(d)
		if !plausibleDomain(d) {
			t.Errorf("invalid domain in the list: %q", d)
		}
		if seen[d] {
			t.Errorf("duplicate domain: %q", d)
		}
		seen[d] = true
	}
}

func TestRecordScanWritesProfile(t *testing.T) {
	dir := t.TempDir()
	results := []ScanResult{
		{Domain: "blocked.example", State: StateBlocked, Evidence: EvidenceTLSStall},
		{Domain: "allowed.example", State: StateAllowed},
	}
	n, err := RecordScanIn(dir, "net", results)
	if err != nil || n != 2 {
		t.Fatalf("recorded %d err %v", n, err)
	}
	profile, err := LoadProfile(ProfilePathIn(dir, "net"), "net")
	if err != nil {
		t.Fatal(err)
	}
	if profile.State("blocked.example", time.Now()) != StateBlocked {
		t.Error("blocked result not recorded")
	}
	if profile.State("allowed.example", time.Now()) != StateAllowed {
		t.Error("allowed result not recorded")
	}
}

func TestRouteCommandsBuildIpRoute(t *testing.T) {
	if runtime.GOOS == "darwin" {
		return
	}
	var got [][]string
	old := routeExec
	routeExec = func(name string, args ...string) *exec.Cmd {
		got = append(got, append([]string{name}, args...))
		return exec.Command("true")
	}
	t.Cleanup(func() { routeExec = old })

	run := routeCommands("wg0")
	if err := run("replace", "151.101.1.140"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if err := run("del", "151.101.1.140"); err != nil {
		t.Fatalf("del: %v", err)
	}
	want := [][]string{
		{"ip", "route", "replace", "151.101.1.140", "dev", "wg0"},
		{"ip", "route", "del", "151.101.1.140", "dev", "wg0"},
	}
	if len(got) != len(want) {
		t.Fatalf("ran %d commands, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if strings.Join(got[i], " ") != strings.Join(want[i], " ") {
			t.Errorf("command %d = %q, want %q", i, got[i], want[i])
		}
	}
	if err := run("bogus", "x"); err == nil {
		t.Error("an unknown verb should be an error, not a silent success")
	}
}
