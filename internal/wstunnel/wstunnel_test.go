package wstunnel

import (
	"log"
	"os"
	"os/exec"
	"testing"
)

// TestWstunnelStopSettlesState proves Stop is synchronous: after it returns,
// the supervised alive flag is already cleared, so the next Ensure cannot
// mistake a dead child for a live relay.
func TestWstunnelStopSettlesState(t *testing.T) {
	w := NewProc("", log.New(os.Stderr, "test: ", 0))
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("sleep not available: %v", err)
	}
	done := make(chan struct{})
	w.mu.Lock()
	w.cmd = cmd
	w.alive = true
	w.done = done
	w.mu.Unlock()
	go func() {
		_ = cmd.Wait()
		w.mu.Lock()
		if w.cmd == cmd {
			w.cmd = nil
			w.alive = false
		}
		close(done)
		w.mu.Unlock()
	}()

	w.Stop()

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.alive {
		t.Error("Stop returned with alive still true; next Ensure would be a stale no-op")
	}
	if w.cmd != nil {
		t.Error("Stop returned with cmd still set")
	}
	select {
	case <-done:
	default:
		t.Error("Stop returned before the reaper settled")
	}
}
