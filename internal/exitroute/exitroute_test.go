package exitroute

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExitBlocked(t *testing.T) {
	cases := []struct {
		name string
		obs  Observation
		want bool
	}{
		{"refused and served", Observation{Cloud: 403, Home: 200}, true},
		{"legal refusal", Observation{Cloud: 451, Home: 200}, true},
		{"rate limit", Observation{Cloud: 429, Home: 200}, true},
		{"cloud unreachable", Observation{Cloud: 0, CloudErr: "tls: handshake failure", Home: 200}, true},
		{"served by both", Observation{Cloud: 200, Home: 200}, false},
		{"site policy on both", Observation{Cloud: 403, Home: 403}, false},
		{"home refused too", Observation{Cloud: 403, Home: 451}, false},
		{"site error", Observation{Cloud: 500, Home: 200}, false},
		{"neither reached", Observation{Cloud: 0, CloudErr: "timeout", Home: 0}, false},
	}
	for _, c := range cases {
		if got := ExitBlocked(c.obs); got != c.want {
			t.Errorf("%s: ExitBlocked = %v, want %v", c.name, got, c.want)
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

func TestReconcile(t *testing.T) {
	add, remove := Reconcile(
		[]string{"1.1.1.0/24", "2.2.2.0/24", "3.3.3.0/24"},
		[]string{"2.2.2.0/24", "4.4.4.0/24"},
	)
	if len(add) != 2 || add[0] != "1.1.1.0/24" || add[1] != "3.3.3.0/24" {
		t.Errorf("add = %v", add)
	}
	if len(remove) != 1 || remove[0] != "4.4.4.0/24" {
		t.Errorf("remove = %v", remove)
	}
}

func TestDesiredDropsExpired(t *testing.T) {
	now := time.Now()
	state := State{Entries: map[string]Entry{
		"1.1.1.0/24": {Prefix: "1.1.1.0/24", Verified: now, Expires: now.Add(time.Hour)},
		"2.2.2.0/24": {Prefix: "2.2.2.0/24", Verified: now.Add(-48 * time.Hour), Expires: now.Add(-24 * time.Hour)},
	}}
	got := Desired(state, now, 0)
	if len(got) != 1 || got[0] != "1.1.1.0/24" {
		t.Fatalf("desired = %v", got)
	}
	Prune(state, now)
	if len(state.Entries) != 1 {
		t.Fatalf("prune left %d entries", len(state.Entries))
	}
}

func TestApplyObservationReleasesDomain(t *testing.T) {
	l := &Learner{state: State{Entries: map[string]Entry{}}}
	now := time.Now()
	l.applyObservation(Observation{
		Domain: "blocked.example", Prefixes: []string{"5.5.5.0/24"},
		Cloud: 403, Home: 200,
	}, now)
	if len(l.state.Entries) != 1 {
		t.Fatalf("blocked observation learned nothing")
	}
	l.applyObservation(Observation{
		Domain: "blocked.example", Prefixes: []string{"5.5.5.0/24"},
		Cloud: 200, Home: 200,
	}, now)
	if len(l.state.Entries) != 0 {
		t.Fatalf("a site the cloud exit serves kept its prefixes: %v", l.state.Entries)
	}
}

func TestCandidatesFromFeed(t *testing.T) {
	dir := t.TempDir()
	feed := `{"version":2,"network_id":"a","domains":{
		"www.reddit.com":{"state":"blocked","evidence":"tls-stall","count":2},
		"poki.com":{"state":"blocked","evidence":"ip-rejected","count":1},
		"google.com":{"state":"allowed","evidence":""}},"protocols":{}}`
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(feed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(feed), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Candidates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("candidates %v", got)
	}
	if got[0].Domain != "poki.com" || got[1].Domain != "www.reddit.com" {
		t.Errorf("candidates %v", got)
	}
	if got[1].Evidence != "tls-stall" || got[1].Count != 2 {
		t.Errorf("reddit candidate %+v", got[1])
	}
}

func TestExtraDomainsSkipsNoise(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains")
	body := "# comment\nreddit.com\n\n10.0.0.1\nlocalhost\nhttp://x\n   x.com  \n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ExtraDomains(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Domain != "reddit.com" || got[1].Domain != "x.com" {
		t.Fatalf("extra domains %v", got)
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now().UTC().Truncate(time.Second)
	state := State{Entries: map[string]Entry{
		"151.101.1.0/24": {Prefix: "151.101.1.0/24", Domain: "www.reddit.com", Cloud: 403, Home: 200, Verified: now, Expires: now.Add(time.Hour)},
	}}
	if err := SaveState(path, state); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := got.Entries["151.101.1.0/24"]
	if !ok || entry.Domain != "www.reddit.com" || !entry.Expires.Equal(state.Entries["151.101.1.0/24"].Expires) {
		t.Fatalf("state round trip: %+v", got)
	}
}
