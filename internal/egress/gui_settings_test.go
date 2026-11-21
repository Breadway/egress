package egress

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRelayRegionCode(t *testing.T) {
	cases := map[string]string{
		"automatic":   "",
		"sydney":      "syd",
		"singapore":   "sin",
		"los_angeles": "lax",
		"bogus":       "",
	}
	for in, want := range cases {
		if got := relayRegionCode(in); got != want {
			t.Errorf("relayRegionCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShareUsagePersistsAndResetsMonthly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EGRESS_STATE_DIR", dir)

	usage := newShareUsage(1)
	usage.mu.Lock()
	usage.baseline = 600_000_000
	usage.max["peer"] = 500_000_000
	usage.mu.Unlock()
	if !usage.Exceeded() {
		t.Fatal("1.1 GB should exceed a 1 GB limit")
	}
	usage.Save()

	reloaded := newShareUsage(1)
	reloaded.mu.Lock()
	got := reloaded.totalLocked()
	reloaded.mu.Unlock()
	if got != 1_100_000_000 {
		t.Fatalf("persisted total = %d, want 1100000000", got)
	}
	if !reloaded.Exceeded() {
		t.Fatal("reloaded usage should still be over the limit")
	}

	// A new calendar month clears the baseline and the per-peer maxima.
	reloaded.mu.Lock()
	reloaded.month = time.Now().AddDate(0, -1, 0).Format("2006-01")
	reloaded.mu.Unlock()
	reloaded.Track("wg-test", nil)
	reloaded.mu.Lock()
	total := reloaded.totalLocked()
	reloaded.mu.Unlock()
	if total != 0 {
		t.Fatalf("total after month change = %d, want 0", total)
	}
	if reloaded.Exceeded() {
		t.Fatal("a fresh month must not exceed the limit")
	}
	if path := filepath.Base(reloaded.path); path != "share-usage.json" {
		t.Fatalf("usage path = %q", reloaded.path)
	}
}

func TestHiddenPeerNeverDialsDirect(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.SetHiddenAddress(true)
	m.setDesired([]apiPeer{{
		PubKey: "friend", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820", Label: "Friend",
	}})
	m.reconcile()
	for _, call := range plat.calls {
		if call.kind == "set" && call.endpoint == "203.0.113.9:51820" {
			t.Fatal("hidden address still dialled the peer directly")
		}
	}
	if len(plat.calls) == 0 {
		t.Fatal("expected the peer to be configured for the star")
	}
}
