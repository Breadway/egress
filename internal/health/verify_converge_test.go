package health

import (
	"testing"
	"time"
)

const (
	testWindow = 100 * time.Millisecond
	testPoll   = 10 * time.Millisecond
)

func TestConvergeTunnelRetriesUntilTheFallbackComesUp(t *testing.T) {
	r := Results{Tunnel: "down", Probe: "failed", Exit: "split"}
	calls := 0
	// The relay handshake lands on the third refresh, like the ~26s delay the
	// supervisor needs after one failed UDP probe.
	r = convergeTunnel(r, testWindow, testPoll, func(r *Results) {
		calls++
		if calls >= 2 {
			r.Tunnel = "up"
			r.Probe = "ok"
		}
	})
	if calls != 2 {
		t.Fatalf("refreshed %d times, want 2", calls)
	}
	if r.Tunnel != "up" || r.Probe != "ok" {
		t.Fatalf("result = %+v, want a settled tunnel", r)
	}
}

func TestConvergeTunnelGivesUpAtTheWindow(t *testing.T) {
	r := Results{Tunnel: "down", Probe: "failed", Exit: "split"}
	calls := 0
	start := time.Now()
	r = convergeTunnel(r, testWindow, testPoll, func(r *Results) { calls++ })
	if calls == 0 {
		t.Fatal("never retried an unsettled tunnel")
	}
	if elapsed := time.Since(start); elapsed > 10*testWindow {
		t.Fatalf("waited %v past a %v window", elapsed, testWindow)
	}
	if r.Tunnel != "down" {
		t.Fatalf("tunnel = %q, want the still-down result", r.Tunnel)
	}
}

func TestConvergeTunnelDoesNotWaitWhenAlreadySettled(t *testing.T) {
	r := Results{Tunnel: "up", Probe: "ok", Exit: "split"}
	calls := 0
	r = convergeTunnel(r, testWindow, testPoll, func(r *Results) { calls++ })
	if calls != 0 {
		t.Fatalf("refreshed %d times on a settled tunnel", calls)
	}
}

func TestConvergeTunnelDoesNotWaitOnAFailedSupervisor(t *testing.T) {
	r := Results{Tunnel: "down", Probe: "failed", Supervisor: "service is not active"}
	calls := 0
	r = convergeTunnel(r, testWindow, testPoll, func(r *Results) { calls++ })
	if calls != 0 {
		t.Fatalf("refreshed %d times after a supervisor failure", calls)
	}
}

func TestConvergeTunnelDoesNotWaitOnAFailedDNS(t *testing.T) {
	r := Results{Tunnel: "down", Probe: "failed", DNS: "no addresses returned"}
	calls := 0
	r = convergeTunnel(r, testWindow, testPoll, func(r *Results) { calls++ })
	if calls != 0 {
		t.Fatalf("refreshed %d times after a DNS failure", calls)
	}
}

func TestConvergeTunnelIgnoresASplitPingFailure(t *testing.T) {
	// In split mode a missing ICMP reply is only a warning; the handshake is
	// the authority, so there is nothing to wait for.
	r := Results{Tunnel: "up", Probe: "failed", Exit: "split"}
	calls := 0
	r = convergeTunnel(r, testWindow, testPoll, func(r *Results) { calls++ })
	if calls != 0 {
		t.Fatalf("refreshed %d times for a split-mode ping warning", calls)
	}
}

func TestConvergeTunnelSkipsWhenNoTunnelIsConfigured(t *testing.T) {
	r := Results{Tunnel: "skipped", Probe: "skipped"}
	calls := 0
	r = convergeTunnel(r, testWindow, testPoll, func(r *Results) { calls++ })
	if calls != 0 {
		t.Fatalf("refreshed %d times without a tunnel", calls)
	}
}
