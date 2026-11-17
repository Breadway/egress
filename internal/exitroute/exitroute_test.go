package exitroute

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCloudRefused(t *testing.T) {
	cases := []struct {
		name  string
		cloud int
		err   string
		want  bool
	}{
		{"forbidden", 403, "", true},
		{"legal", 451, "", true},
		{"rate limited", 429, "", true},
		{"no response", 0, "tls: handshake failure", true},
		{"certificate name", 0, "x509: certificate is valid for other.example, not this.example", false},
		{"served", 200, "", false},
		{"redirect", 302, "", false},
		{"server error", 500, "", false},
		{"unknown", 0, "", false},
	}
	for _, c := range cases {
		var err error
		if c.cloud == 0 && c.err != "" {
			var xerr x509.HostnameError
			if c.name == "certificate name" {
				err = xerr
			} else {
				err = errors.New(c.err)
			}
		}
		if got := CloudRefused(c.cloud, err); got != c.want {
			t.Errorf("%s: CloudRefused(%d, %v) = %v, want %v", c.name, c.cloud, err, got, c.want)
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
	l        *Learner
	allowed  map[string]string
	routes   map[string]bool
	direct   *http.Client
	probeSet int
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
	h := &harness{l: l, allowed: map[string]string{}, routes: map[string]bool{}, direct: l.direct}
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

// route marks a prefix as already routed, as the kernel would after a cycle.
func (h *harness) route(prefix string) {
	h.routes[prefix] = true
	h.l.applied[prefix] = true
}

func healthyNow(exits ...Exit) map[string]int64 {
	hs := map[string]int64{}
	for _, exit := range exits {
		hs[exit.PubKey] = time.Now().Unix()
	}
	return hs
}

func TestDecideKeepsHealthyOwner(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true, Priority: 10}
	b := Exit{ID: "b", PubKey: "pb", Enabled: true, Priority: 20}
	h := newHarness(t, a, b)
	h.l.state.Assignments["151.101.1.0/24"] = "a"
	h.l.probeFn = func(ctx context.Context, client *http.Client, domain string) (int, error) {
		if client == h.direct && h.owner("151.101.1.0/24") == "a" {
			return 200, nil
		}
		return 403, nil
	}
	site := h.l.decide(context.Background(), resolved{
		domain: "www.reddit.com", prefixes: []string{"151.101.1.0/24"}, cloud: 403, ok: true,
	}, healthyNow(a, b), time.Now())
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
	h.l.probeFn = func(ctx context.Context, client *http.Client, domain string) (int, error) {
		if client == h.direct && h.owner("151.101.1.0/24") == "b" {
			return 200, nil
		}
		return 403, nil
	}
	site := h.l.decide(context.Background(), resolved{
		domain: "www.reddit.com", prefixes: []string{"151.101.1.0/24"}, cloud: 403, ok: true,
	}, healthyNow(a, b), time.Now())
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
	probes := 0
	h.l.probeFn = func(ctx context.Context, client *http.Client, domain string) (int, error) {
		probes++
		if h.owner("151.101.1.0/24") == "b" {
			return 200, nil
		}
		return 403, nil
	}
	hs := map[string]int64{"pb": time.Now().Unix(), "pa": time.Now().Add(-time.Hour).Unix()}
	site := h.l.decide(context.Background(), resolved{
		domain: "www.reddit.com", prefixes: []string{"151.101.1.0/24"}, cloud: 403, ok: true,
	}, hs, time.Now())
	if site.Exit != "b" {
		t.Fatalf("site %+v, want b", site)
	}
	if probes == 0 {
		t.Fatal("no probe ran")
	}
}

func TestDecideUnserved(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true}
	h := newHarness(t, a)
	h.l.state.Assignments["151.101.1.0/24"] = "a"
	h.route("151.101.1.0/24")
	h.l.probeFn = func(ctx context.Context, client *http.Client, domain string) (int, error) {
		return 403, nil
	}
	site := h.l.decide(context.Background(), resolved{
		domain: "www.reddit.com", prefixes: []string{"151.101.1.0/24"}, cloud: 403, ok: true,
	}, healthyNow(a), time.Now())
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

func TestDecideReleasesWhenCloudServes(t *testing.T) {
	a := Exit{ID: "a", PubKey: "pa", Enabled: true}
	h := newHarness(t, a)
	h.l.state.Assignments["151.101.1.0/24"] = "a"
	h.route("151.101.1.0/24")
	site := h.l.decide(context.Background(), resolved{
		domain: "www.reddit.com", prefixes: []string{"151.101.1.0/24"}, cloud: 200, ok: true,
	}, healthyNow(a), time.Now())
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
	h.l.probeFn = func(ctx context.Context, client *http.Client, domain string) (int, error) {
		tried = h.owner("151.101.1.0/24")
		if tried == "b" {
			return 200, nil
		}
		return 403, nil
	}
	site := h.l.decide(context.Background(), resolved{
		domain: "www.reddit.com", prefixes: []string{"151.101.1.0/24"}, cloud: 403, ok: true,
	}, healthyNow(a, b), time.Now())
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
