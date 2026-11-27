package exitroute

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeWorks(t *testing.T) {
	cases := []struct {
		name string
		res  ProbeResult
		want bool
	}{
		{"served", ProbeResult{Handshake: true, Status: 200}, true},
		{"redirect", ProbeResult{Handshake: true, Status: 302}, true},
		{"closed after handshake", ProbeResult{Handshake: true}, true},
		{"forbidden with a block page", ProbeResult{Handshake: true, Status: 403, BlockPage: "fortigate"}, false},
		{"application forbidden", ProbeResult{Handshake: true, Status: 403}, true},
		{"legal refusal with a block page", ProbeResult{Handshake: true, Status: 451, BlockPage: "fortigate"}, false},
		{"rate limited", ProbeResult{Handshake: true, Status: 429}, true},
		{"handshake failed", ProbeResult{Err: os.ErrDeadlineExceeded}, false},
		{"no handshake no status", ProbeResult{}, false},
	}
	for _, c := range cases {
		if got := c.res.Works(); got != c.want {
			t.Errorf("%s: Works() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPrefixesFor(t *testing.T) {
	got := PrefixesFor([]string{
		"151.101.1.140", "151.101.1.141", "151.101.65.140",
		"10.0.0.5", "127.0.0.1", "192.168.1.10", "100.64.0.1", "224.0.0.1",
		"2606:4700::6810:1", "not-an-ip", "",
	})
	want := []string{"151.101.1.0/24", "151.101.65.0/24"}
	if len(got) != len(want) {
		t.Fatalf("prefixes %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("prefixes %v, want %v", got, want)
		}
	}
}

func TestRegistryDefaultsAndOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exits.json")
	reg := Registry{Exits: []Exit{
		{ID: "late", PubKey: "k2", Enabled: true, Priority: 20},
		{ID: "early", PubKey: "k1", Enabled: true, Priority: 10, MaxPrefixes: 50},
		{ID: "off", PubKey: "k3", Enabled: false},
	}}
	if err := SaveRegistry(path, reg); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	ordered := EnabledExits(got)
	if len(ordered) != 2 || ordered[0].ID != "early" || ordered[1].ID != "late" {
		t.Fatalf("enabled exits %v", ordered)
	}
	if ordered[0].MaxPrefixes != 50 {
		t.Errorf("max prefixes %d, want 50", ordered[0].MaxPrefixes)
	}
	if ordered[1].MaxPrefixes != 200 {
		t.Errorf("default max prefixes %d, want 200", ordered[1].MaxPrefixes)
	}
	for _, exit := range got.Exits {
		if exit.ID == "off" && exit.Priority != 100 {
			t.Errorf("default priority %d, want 100", exit.Priority)
		}
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now().UTC().Truncate(time.Second)
	state := State{
		Sites: map[string]Site{"www.reddit.com": {
			Domain: "www.reddit.com", Prefixes: []string{"151.101.1.0/24"},
			Cloud: 403, Exit: "hestia", State: SiteExit, Verified: now, Expires: now.Add(time.Hour),
		}},
		Assignments: map[string]string{"151.101.1.0/24": "hestia"},
	}
	if err := SaveState(path, state); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	site, ok := got.Sites["www.reddit.com"]
	if !ok || site.Exit != "hestia" || got.Assignments["151.101.1.0/24"] != "hestia" {
		t.Fatalf("state round trip: %+v", got)
	}
}

type harness struct {
	l       *Learner
	allowed map[string]string
	routes  map[string]bool
}

func newHarness(t *testing.T, exits ...Exit) *harness {
	t.Helper()
	dir := t.TempDir()
	l, err := New(Options{
		FeedDir:      filepath.Join(dir, "feed"),
		ExtraDomains: filepath.Join(dir, "extra"),
		StatePath:    filepath.Join(dir, "state.json"),
		RegistryPath: filepath.Join(dir, "exits.json"),
		Dev:          "wg0",
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range exits {
		if exits[i].Priority == 0 {
			exits[i].Priority = 100
		}
		if exits[i].MaxPrefixes == 0 {
			exits[i].MaxPrefixes = 200
		}
	}
	reg := Registry{Exits: exits}
	l.reg = reg
	l.exits = EnabledExits(reg)
	h := &harness{l: l, allowed: map[string]string{}, routes: map[string]bool{}}
	l.setAllowed = func(dev, pub, list string) error {
		h.allowed[pub] = list
		return nil
	}
	l.addRouteFn = func(prefix string) error {
		h.routes[prefix] = true
		return nil
	}
	l.delRouteFn = func(prefix string) error {
		delete(h.routes, prefix)
		return nil
	}
	return h
}

func (h *harness) owner(prefix string) string { return h.l.state.Assignments[prefix] }

func TestApplyAllowedIncludesExitAddress(t *testing.T) {
	h := newHarness(t, Exit{ID: "hestia", PubKey: "hestia-key", Address: "10.99.0.2", Enabled: true})
	h.l.state.Assignments = map[string]string{"104.18.0.0/16": "hestia"}
	h.l.applyAllowed("hestia")
	got := h.allowed["hestia-key"]
	if !strings.Contains(got, "104.18.0.0/16") || !strings.Contains(got, "10.99.0.2/32") {
		t.Fatalf("allowed = %q, want the prefix and the exit address", got)
	}
}

// route marks a prefix as already routed, as the kernel would after a cycle.
func (h *harness) route(prefix string) {
	h.routes[prefix] = true
	h.l.applied[prefix] = true
}

// pathProbe returns 200 only when the prefix is assigned to exit id.
func (h *harness) pathProbe(prefix, id string) {
	h.l.probeFn = func(ctx context.Context, domain, ip string, mark int) ProbeResult {
		if h.owner(prefix) == id {
			return ProbeResult{Handshake: true, Status: 200}
		}
		return ProbeResult{Handshake: true, Status: 403, BlockPage: "fortigate"}
	}
}

func healthyNow(exits ...Exit) map[string]int64 {
	hs := map[string]int64{}
	for _, exit := range exits {
		hs[exit.PubKey] = time.Now().Unix()
	}
	return hs
}

func resolvedSite(domain, prefix string) resolved {
	return resolved{
		domain: domain, prefixes: []string{prefix}, ips: []string{"203.0.113.10"},
		cloud: ProbeResult{Handshake: true, Status: 403, BlockPage: "fortigate"}, ok: true,
	}
}

func TestDecideKeepsHealthyOwner(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true, Priority: 10}
	b := Exit{ID: "b", PubKey: "pb", Enabled: true, Priority: 20}
	h := newHarness(t, a, b)
	h.l.state.Assignments["151.101.1.0/24"] = "a"
	h.pathProbe("151.101.1.0/24", "a")
	site := h.l.decide(context.Background(), resolvedSite("www.reddit.com", "151.101.1.0/24"), healthyNow(a, b), time.Now())
	if site.State != SiteExit || site.Exit != "a" {
		t.Fatalf("site %+v, want exit a", site)
	}
	if got := h.owner("151.101.1.0/24"); got != "a" {
		t.Fatalf("owner moved to %q", got)
	}
}

func TestDecideFailsOver(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true, Priority: 10}
	b := Exit{ID: "b", PubKey: "pb", Enabled: true, Priority: 20}
	h := newHarness(t, a, b)
	h.l.state.Assignments["151.101.1.0/24"] = "a"
	h.pathProbe("151.101.1.0/24", "b")
	site := h.l.decide(context.Background(), resolvedSite("www.reddit.com", "151.101.1.0/24"), healthyNow(a, b), time.Now())
	if site.State != SiteExit || site.Exit != "b" {
		t.Fatalf("site %+v, want exit b", site)
	}
	if got := h.owner("151.101.1.0/24"); got != "b" {
		t.Fatalf("owner %q, want b", got)
	}
	if h.allowed["pa"] != "" {
		t.Errorf("exit a kept %q", h.allowed["pa"])
	}
	if h.allowed["pb"] != "151.101.1.0/24" {
		t.Errorf("exit b carries %q", h.allowed["pb"])
	}
	if !h.routes["151.101.1.0/24"] {
		t.Error("route missing after failover")
	}
}

func TestDecideSkipsUnhealthyExit(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true, Priority: 10}
	b := Exit{ID: "b", PubKey: "pb", Enabled: true, Priority: 20}
	h := newHarness(t, a, b)
	h.pathProbe("151.101.1.0/24", "b")
	hs := map[string]int64{"pb": time.Now().Unix(), "pa": time.Now().Add(-time.Hour).Unix()}
	site := h.l.decide(context.Background(), resolvedSite("www.reddit.com", "151.101.1.0/24"), hs, time.Now())
	if site.Exit != "b" {
		t.Fatalf("site %+v, want b", site)
	}
}

func TestDecideUnserved(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true}
	h := newHarness(t, a)
	h.l.state.Assignments["151.101.1.0/24"] = "a"
	h.route("151.101.1.0/24")
	h.l.probeFn = func(ctx context.Context, domain, ip string, mark int) ProbeResult {
		return ProbeResult{Handshake: true, Status: 403, BlockPage: "fortigate"}
	}
	site := h.l.decide(context.Background(), resolvedSite("www.reddit.com", "151.101.1.0/24"), healthyNow(a), time.Now())
	if site.State != SiteUnserved {
		t.Fatalf("site %+v, want unserved", site)
	}
	if _, ok := h.l.state.Assignments["151.101.1.0/24"]; ok {
		t.Error("unserved prefix still assigned")
	}
	if h.routes["151.101.1.0/24"] {
		t.Error("unserved prefix still routed")
	}
}

func TestDecideReprobesDirectBeforeUnserved(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true}
	h := newHarness(t, a)
	h.l.state.Assignments["151.101.1.0/24"] = "a"
	h.route("151.101.1.0/24")
	// The first cloud probe saw a block page, so the site is tentatively
	// unserved. The direct re-probe reaches it, which must win.
	h.l.probeFn = func(ctx context.Context, domain, ip string, mark int) ProbeResult {
		if mark == CloudMark {
			return ProbeResult{Handshake: true, Status: 200}
		}
		return ProbeResult{Handshake: true, Status: 403, BlockPage: "fortigate"}
	}
	r := resolvedSite("www.reddit.com", "151.101.1.0/24")
	site := h.l.decide(context.Background(), r, healthyNow(a), time.Now())
	if site.State != SiteCloud {
		t.Fatalf("site %+v, want cloud when the direct path answers", site)
	}
	if _, ok := h.l.state.Assignments["151.101.1.0/24"]; ok {
		t.Error("a direct site stayed assigned to an exit")
	}
	if h.routes["151.101.1.0/24"] {
		t.Error("a direct site stayed routed into the tunnel")
	}
}

func TestDecideReleasesWhenCloudServes(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true}
	h := newHarness(t, a)
	h.l.state.Assignments["151.101.1.0/24"] = "a"
	h.route("151.101.1.0/24")
	r := resolvedSite("www.reddit.com", "151.101.1.0/24")
	r.cloud = ProbeResult{Handshake: true, Status: 200}
	site := h.l.decide(context.Background(), r, healthyNow(a), time.Now())
	if site.State != SiteCloud {
		t.Fatalf("site %+v, want cloud", site)
	}
	if len(h.l.state.Assignments) != 0 {
		t.Errorf("assignments left: %v", h.l.state.Assignments)
	}
	if h.routes["151.101.1.0/24"] {
		t.Error("route left behind")
	}
}

func TestDecideReleasesWhenCloudClosesAfterHandshake(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true}
	h := newHarness(t, a)
	h.l.state.Assignments["104.16.79.0/24"] = "a"
	h.route("104.16.79.0/24")
	r := resolvedSite("static.cloudflareinsights.com", "104.16.79.0/24")
	r.cloud = ProbeResult{Handshake: true}
	site := h.l.decide(context.Background(), r, healthyNow(a), time.Now())
	if site.State != SiteCloud {
		t.Fatalf("site %+v: a host that closes on / still proves the cloud path works", site)
	}
}

func TestDecideSkipsExitWhoseNetworkBlocksDomain(t *testing.T) {
	dir := t.TempDir()
	feed := `{"version":2,"domains":{"www.reddit.com":{"state":"blocked","evidence":"tls-stall","count":1}}}`
	if err := os.WriteFile(filepath.Join(dir, "net-a.json"), []byte(feed), 0600); err != nil {
		t.Fatal(err)
	}
	a := Exit{ID: "a", PubKey: "pa", Enabled: true, Priority: 10, Network: "net-a"}
	b := Exit{ID: "b", PubKey: "pb", Enabled: true, Priority: 20}
	h := newHarness(t, a, b)
	h.l.opts.FeedDir = dir
	tried := ""
	h.l.probeFn = func(ctx context.Context, domain, ip string, mark int) ProbeResult {
		tried = h.owner("151.101.1.0/24")
		if tried == "b" {
			return ProbeResult{Handshake: true, Status: 200}
		}
		return ProbeResult{Handshake: true, Status: 403, BlockPage: "fortigate"}
	}
	site := h.l.decide(context.Background(), resolvedSite("www.reddit.com", "151.101.1.0/24"), healthyNow(a, b), time.Now())
	if site.Exit != "b" {
		t.Fatalf("site %+v, want b (a reports the site blocked)", site)
	}
	if tried == "a" {
		t.Error("the blocked exit was probed anyway")
	}
}

func TestOwnerConflictReleases(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true}
	b := Exit{ID: "b", PubKey: "pb", Enabled: true}
	h := newHarness(t, a, b)
	h.l.state.Assignments["1.1.1.0/24"] = "a"
	h.l.state.Assignments["2.2.2.0/24"] = "b"
	if got := h.l.ownerOf([]string{"1.1.1.0/24", "2.2.2.0/24"}); got != "" {
		t.Fatalf("ownerOf = %q, want empty after conflict", got)
	}
	if len(h.l.state.Assignments) != 0 {
		t.Errorf("conflicting assignments left: %v", h.l.state.Assignments)
	}
}

func TestPruneReleasesExpired(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true}
	h := newHarness(t, a)
	now := time.Now()
	h.l.state.Sites["old.example"] = Site{
		Domain: "old.example", Prefixes: []string{"1.1.1.0/24"}, State: SiteExit, Exit: "a",
		Expires: now.Add(-time.Hour),
	}
	h.l.state.Assignments["1.1.1.0/24"] = "a"
	h.l.prune(map[string]bool{}, now)
	if len(h.l.state.Sites) != 0 || len(h.l.state.Assignments) != 0 {
		t.Fatalf("expired site survived: %+v", h.l.state)
	}
}

func TestStatusUnserved(t *testing.T) {
	status := Status{Sites: map[string]Site{
		"a.example": {State: SiteExit, Exit: "hestia"},
		"b.example": {State: SiteUnserved},
		"c.example": {State: SiteCloud},
	}}
	got := status.UnservedDomains()
	if len(got) != 1 || got[0] != "b.example" {
		t.Fatalf("unserved %v", got)
	}
	data, err := json.Marshal(status)
	if err != nil || len(data) == 0 {
		t.Fatalf("status marshal: %v", err)
	}
}
