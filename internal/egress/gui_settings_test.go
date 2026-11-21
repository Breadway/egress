package egress

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	usage.total = 1_100_000_000
	usage.last["peer"] = 1_100_000_000
	usage.mu.Unlock()
	if !usage.Exceeded() {
		t.Fatal("1.1 GB should exceed a 1 GB limit")
	}
	usage.Save()

	reloaded := newShareUsage(1)
	reloaded.mu.Lock()
	got := reloaded.total
	reloaded.mu.Unlock()
	if got != 1_100_000_000 {
		t.Fatalf("persisted total = %d, want 1100000000", got)
	}
	if !reloaded.Exceeded() {
		t.Fatal("reloaded usage should still be over the limit")
	}

	// A new calendar month clears the total and the per-peer baselines.
	reloaded.mu.Lock()
	reloaded.month = time.Now().AddDate(0, -1, 0).Format("2006-01")
	reloaded.mu.Unlock()
	reloaded.Track("wg-test", nil)
	reloaded.mu.Lock()
	total := reloaded.total
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

func TestShareUsageCountsDeltasAcrossReconnects(t *testing.T) {
	t.Setenv("EGRESS_STATE_DIR", t.TempDir())
	previous := wgTransferCommand
	t.Cleanup(func() { wgTransferCommand = previous })

	current := map[string]uint64{"peer": 100}
	wgTransferCommand = func(string) map[string]uint64 { return current }
	active := map[string]exitClient{"peer": {}}

	usage := newShareUsage(100)
	usage.Track("wg-test", active)
	usage.mu.Lock()
	first := usage.total
	usage.mu.Unlock()
	if first != 100 {
		t.Fatalf("first sample = %d, want 100", first)
	}

	current = map[string]uint64{"peer": 150}
	usage.Track("wg-test", active)
	usage.mu.Lock()
	second := usage.total
	usage.mu.Unlock()
	if second != 150 {
		t.Fatalf("delta sample = %d, want 150", second)
	}

	// The peer reconnects and the kernel counter restarts at a small value.
	current = map[string]uint64{"peer": 20}
	usage.Track("wg-test", active)
	usage.mu.Lock()
	afterReset := usage.total
	usage.mu.Unlock()
	if afterReset != 170 {
		t.Fatalf("after counter reset = %d, want 170", afterReset)
	}

	// A restart with the interface still up sees the old counters again. The
	// persisted per-peer baseline keeps that from counting twice.
	usage.Save()
	reloaded := newShareUsage(100)
	reloaded.Track("wg-test", active)
	reloaded.mu.Lock()
	afterRestart := reloaded.total
	reloaded.mu.Unlock()
	if afterRestart != 170 {
		t.Fatalf("after restart = %d, want 170", afterRestart)
	}

	// Removing the peer stops sampling it without losing what was counted.
	usage.Track("wg-test", map[string]exitClient{})
	usage.mu.Lock()
	afterRemove := usage.total
	usage.mu.Unlock()
	if afterRemove != 170 {
		t.Fatalf("after removal = %d, want 170", afterRemove)
	}
}

func TestPeerSnapshotNeverUsesAddressAsName(t *testing.T) {
	m := newTestManager(&fakePeerPlatform{})
	m.setDesired([]apiPeer{{
		PubKey: "unlabeled", IP: "10.88.0.44", Endpoint: "203.0.113.9:51820",
	}})
	if views := m.Snapshot(); len(views) != 0 {
		t.Fatalf("unlabeled peer leaked into the UI: %+v", views)
	}
	m.setDesired([]apiPeer{{
		PubKey: "labeled", IP: "10.88.0.45", Endpoint: "203.0.113.9:51821", Label: "Hestia",
	}})
	views := m.Snapshot()
	if len(views) != 1 || views[0].Name != "Hestia" {
		t.Fatalf("labeled peer snapshot = %+v", views)
	}
	for _, v := range views {
		if strings.Contains(v.Name, "10.88.") {
			t.Fatalf("address used as a display name: %q", v.Name)
		}
	}
}

func TestDERPRegionAccessor(t *testing.T) {
	if got := (&derpTransport{preferred: "sin", region: "syd"}).Region(); got != "sin" {
		t.Fatalf("preferred region = %q, want sin", got)
	}
	if got := (&derpTransport{region: "lax"}).Region(); got != "lax" {
		t.Fatalf("connected region = %q, want lax", got)
	}
}

func TestExitShareStartsAndStopsOnce(t *testing.T) {
	previous := runExitServer
	t.Cleanup(func() { runExitServer = previous })
	var starts, stops atomic.Int32
	runExitServer = func(ctx context.Context, _ exitServeOptions) error {
		starts.Add(1)
		<-ctx.Done()
		stops.Add(1)
		return nil
	}

	share := newExitShare()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waitFor := func(value *atomic.Int32, want int32) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for value.Load() != want {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %d, have %d", want, value.Load())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	opts := defaultExitServeOptions()
	opts.LimitGB = 10
	share.Apply(ctx, true, opts)
	waitFor(&starts, 1)

	// Re-applying the same options must not open a second server.
	share.Apply(ctx, true, opts)
	time.Sleep(50 * time.Millisecond)
	if got := starts.Load(); got != 1 {
		t.Fatalf("starts after identical apply = %d, want 1", got)
	}

	share.Apply(ctx, false, opts)
	waitFor(&stops, 1)

	changed := opts
	changed.LimitGB = 20
	share.Apply(ctx, true, changed)
	waitFor(&starts, 2)
	share.Stop()
	waitFor(&stops, 2)
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
