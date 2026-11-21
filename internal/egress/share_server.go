package egress

import (
	"context"
	"errors"
	"sync"
	"time"
)

// exitShare starts and stops this device's exit server when the user changes
// the sharing setting. Options are comparable, so re-applying the same values
// leaves a running server alone.
type exitShare struct {
	// applyMu serializes Apply calls. Two settings updates arriving together
	// must not both decide the server is stopped and start one each.
	applyMu sync.Mutex
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	opts    exitServeOptions
}

func newExitShare() *exitShare { return &exitShare{} }

// Apply reconciles the server with the requested state. Starting or stopping
// is asynchronous; the caller does not wait for peers to drain.
func (s *exitShare) Apply(parent context.Context, enabled bool, opts exitServeOptions) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.mu.Lock()
	if enabled && s.cancel != nil && s.opts == opts {
		s.mu.Unlock()
		return
	}
	cancel, done := s.cancel, s.done
	s.cancel, s.done = nil, nil
	s.opts = opts
	s.mu.Unlock()

	if cancel != nil {
		cancel()
		if done != nil {
			<-done
		}
	}
	if !enabled {
		return
	}

	ctx, stop := context.WithCancel(parent)
	finished := make(chan struct{})
	s.mu.Lock()
	s.cancel, s.done = stop, finished
	s.mu.Unlock()
	go func() {
		defer close(finished)
		for {
			err := runExitServer(ctx, opts)
			if ctx.Err() != nil {
				break
			}
			if errors.Is(err, errShareLimit) {
				next := time.Date(time.Now().Year(), time.Now().Month()+1, 1, 0, 0, 0, 0, time.Local)
				appLogger().Printf("share: limit reached; resuming on %s", next.Format("2 January"))
				select {
				case <-ctx.Done():
				case <-time.After(time.Until(next)):
				}
				continue
			}
			if err == nil {
				break
			}
			appLogger().Printf("share: %v; retrying in 30s", err)
			select {
			case <-ctx.Done():
			case <-time.After(30 * time.Second):
			}
		}
		s.mu.Lock()
		if s.done == finished {
			s.cancel, s.done = nil, nil
		}
		s.mu.Unlock()
	}()
}

// Stop ends sharing if it is running.
func (s *exitShare) Stop() {
	s.Apply(context.Background(), false, exitServeOptions{})
}
