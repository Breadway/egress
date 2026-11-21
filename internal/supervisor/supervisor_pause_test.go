package supervisor

import (
	"io"
	"log"
	"testing"
	"time"
)

type pauseFake struct {
	relayFake
	up     bool
	starts int
	stops  int
}

func (f *pauseFake) StartTunnel() error { f.starts++; f.up = true; return nil }
func (f *pauseFake) StopTunnel() error  { f.stops++; f.up = false; return nil }
func (f *pauseFake) TunnelUp() bool     { return f.up }

// TestPauseResume is the contract the GUI connection button relies on: pause
// stops the interface, resume starts it, and neither touches the service.
func TestPauseResume(t *testing.T) {
	plat := &pauseFake{up: true}
	sup := New(plat, nil, nil, log.New(io.Discard, "", 0), true, true)

	if !sup.Connected() {
		t.Fatal("expected connected while the tunnel is up and not paused")
	}
	if err := sup.SetConnected(false); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if !sup.Paused() || sup.Connected() || plat.up {
		t.Fatalf("pause did not stop the tunnel: paused=%v connected=%v up=%v", sup.Paused(), sup.Connected(), plat.up)
	}
	if plat.stops != 1 {
		t.Fatalf("stops = %d, want 1", plat.stops)
	}
	if err := sup.SetConnected(false); err != nil {
		t.Fatalf("second pause: %v", err)
	}
	if plat.stops != 1 {
		t.Fatalf("second pause repeated teardown: %d stops", plat.stops)
	}
	if err := sup.SetConnected(true); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if sup.Paused() || !sup.Connected() || plat.starts != 1 {
		t.Fatalf("resume failed: paused=%v connected=%v starts=%d", sup.Paused(), sup.Connected(), plat.starts)
	}
}

func TestPauseWaitsForRunLock(t *testing.T) {
	plat := &pauseFake{up: true}
	sup := New(plat, nil, nil, log.New(io.Discard, "", 0), true, true)

	// Simulate a tick that is inside its tunnel-start critical section. A
	// pause must not slip in between the pause check and StartTunnel.
	sup.runMu.Lock()
	done := make(chan struct{})
	go func() {
		_ = sup.SetConnected(false)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("pause did not wait for the run lock")
	case <-time.After(30 * time.Millisecond):
	}
	sup.runMu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pause did not finish after the run lock was released")
	}
	if !sup.Paused() || plat.up {
		t.Fatalf("pause after lock: paused=%v up=%v", sup.Paused(), plat.up)
	}
}

func TestFallbackToggle(t *testing.T) {
	plat := &pauseFake{up: true}
	sup := New(plat, nil, nil, log.New(io.Discard, "", 0), true, true)
	if !sup.Fallback() {
		t.Fatal("fallback should default on")
	}
	sup.SetFallback(false)
	if sup.Fallback() {
		t.Fatal("fallback should be off")
	}
	sup.SetFallback(true)
	if !sup.Fallback() {
		t.Fatal("fallback should be back on")
	}
}

func TestPathStartsDirect(t *testing.T) {
	plat := &pauseFake{up: true}
	sup := New(plat, nil, nil, log.New(io.Discard, "", 0), true, true)
	if got := sup.Path(); got != "direct" {
		t.Fatalf("path = %q, want direct", got)
	}
	sup.setPath("cloud")
	if got := sup.Path(); got != "cloud" {
		t.Fatalf("path = %q, want cloud", got)
	}
}
