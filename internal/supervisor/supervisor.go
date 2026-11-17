package supervisor

import (
	"context"
	"egress/internal/core"
	"egress/internal/doh"
	"egress/internal/health"
	"egress/internal/logx"
	"egress/internal/platform"
	"egress/internal/split"
	"egress/internal/wstunnel"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"time"
)

type pathState int

const (
	pathUDP pathState = iota
	pathWebSocket
)

// Supervisor keeps the DoH resolver running and moves the WireGuard exit
// between the direct UDP path and the WebSocket fallback.
//
// The health signal is a probe of Aegis's tunnel address, not the WireGuard
// handshake: while the fallback carries traffic the handshake stays fresh
// through it, so handshake age cannot tell a working UDP path from a rescued
// one.
type Supervisor struct {
	plat     platform.Interface
	resolver *doh.Resolver
	tcfg     core.TunnelConfig
	wst      *wstunnel.Proc
	log      *log.Logger

	manageTunnel   bool
	manageFallback bool
	// preferRelay starts the loop on the WebSocket path because the stored
	// protocol picture says UDP is blocked on this network.
	PreferRelay bool

	Iface   string
	Gateway string

	// Candidate default routes, best first, with the index currently
	// pinned. On sustained probe failure the pin walks the list so one dead
	// interface cannot strand the tunnel, DNS and fallback together.
	routes []platform.Route
	pinIdx int

	// Consecutive failed probes while on the relay path. A listening relay
	// port does not prove the WebSocket underneath is alive, so the relay
	// gets its own short-window probes and a restart after sustained
	// failure instead of silence until the next UDP trial.
	relayFailures int

	// DoH wedge tracking. The listener can stay open while every lookup
	// fails, and the relay child resolves through that listener, so this
	// is a whole-stack failure, not a DNS-only one.
	dnsWedgeSince   time.Time
	lastDNSRecovery time.Time

	// split, when set, learns blocked domains from DNS and routes only those
	// destinations into the tunnel.
	Split *split.Controller

	// Tunneler restores. Security software can quarantine wstunnel.exe, and
	// this loop re-extracts the embedded copy on every tick. Unbounded, that
	// is a fight the scanner wins: the file disappears again before it is
	// used, and nothing in the log says why. After a few consecutive
	// restores, say so once and stop trying for a while.
	restores      int
	restorePaused time.Time
}

// A scanner that removes the tunneler removes it again within seconds, so a
// short run of restores means quarantine rather than a one-off deletion.
const (
	tunnelerRestoreLimit = 3
	tunnelerRestorePause = time.Hour
)

func New(plat platform.Interface, resolver *doh.Resolver, wst *wstunnel.Proc, logger *log.Logger, manageTunnel, manageFallback bool) *Supervisor {
	return &Supervisor{
		plat:           plat,
		resolver:       resolver,
		wst:            wst,
		log:            logger,
		manageTunnel:   manageTunnel,
		manageFallback: manageFallback,
	}
}

func (s *Supervisor) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- s.resolver.Serve(ctx) }()
	if s.Split != nil {
		network := split.NetworkKey("", s.Gateway)
		s.Split.SetNetwork(network, s.Iface)
		s.resolver.SetObserver(func(domain string, ips []net.IP, ttl time.Duration) {
			s.Split.HandleAnswer(domain, ips, ttl)
		})
		go s.Split.Run(ctx)
		s.log.Printf("split mode: learned-blocked destinations only (%s)", network)
	}
	if s.manageTunnel {
		go func() { errCh <- s.loop(ctx) }()
	} else {
		// DNS-only mode still owns the resolver: DHCP renews and roams
		// reset the adapter resolver, and nothing else restores 127.0.0.1.
		go func() { errCh <- s.dnsLoop(ctx) }()
	}

	select {
	case <-ctx.Done():
		s.wst.Stop()
		return nil
	case err := <-errCh:
		s.wst.Stop()
		return err
	}
}

func (s *Supervisor) loop(ctx context.Context) error {
	state := pathUDP
	failures := 0
	if s.PreferRelay && s.manageFallback {
		if err := s.enterWebSocket(ctx); err != nil {
			s.log.Printf("relay start failed, trying udp: %v", err)
		} else {
			state = pathWebSocket
			s.log.Printf("starting on the websocket path: the profile says udp is blocked")
		}
	}
	lastTrial := time.Time{}
	if state == pathWebSocket {
		lastTrial = time.Now()
	}
	var lastDNSCheck time.Time

	if !s.plat.TunnelUp() {
		if err := s.plat.StartTunnel(); err != nil {
			s.log.Printf("could not start the tunnel: %v", err)
		}
	}

	// Re-assert the resolver as soon as the loop starts. After a reboot the
	// adapter may have been reset to DHCP, and after `enable` this is what
	// restores DNS without waiting a full core.DNSCheckEvery.
	if s.Iface != "" {
		if err := s.plat.EnsureDNS(s.Iface, s.Gateway); err != nil {
			s.log.Printf("dns apply at startup failed: %v", err)
		}
	}

	ticker := time.NewTicker(core.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		logx.Debugf("tick: state=%d failures=%d tunnel=%v iface=%s gateway=%s",
			state, failures, s.plat.TunnelUp(), s.Iface, s.Gateway)

		// changed tracks a fresh route flip for this tick only. The first
		// probe after a flip fails over immediately instead of waiting out
		// another full round, because a flip usually means the old path is
		// gone, not merely lossy.
		changed := false

		// Deliver a spooled install report from a previous failed run, if any.
		// Cheap when there is nothing to send: one stat call.
		health.FlushPendingReport()

		// Defender can quarantine the tunneler after install. Restore it from
		// the embedded copy: this process runs as SYSTEM and may write there,
		// while the per-user proxy may not. Back off when the file keeps
		// disappearing, because then the scan is the cause, not a bad copy.
		if s.manageFallback {
			if _, err := s.plat.WstunnelPath(); err != nil {
				if time.Now().Before(s.restorePaused) {
					// Deliberately quiet: noteRestore already explained it.
				} else if path, ierr := s.plat.InstallWstunnel(); ierr != nil {
					s.log.Printf("tunneler missing and could not be restored: %v", ierr)
				} else {
					s.noteRestore(path)
				}
			} else if s.restores > 0 {
				s.restores = 0
			}
		}

		// Track the whole default-route set, not just the best route. A new
		// escape path can appear (or vanish) without the best route
		// changing, and a best route can go dead while staying selected.
		if routes, err := s.plat.DefaultRoutes(); err == nil {
			if !sameRouteSet(routes, s.routes) {
				bestChanged := len(routes) == 0 || len(s.routes) == 0 ||
					routes[0] != s.routes[0]
				s.routes = routes
				if bestChanged && len(routes) > 0 {
					s.Iface, s.Gateway = routes[0].Iface, routes[0].Gateway
					s.resolver.SetGateway(s.Gateway)
					// Drop pooled connections bound to the old interface.
					s.resolver.CloseIdle()
					if err := s.plat.ApplyDNS(s.Iface, s.Gateway); err != nil {
						s.log.Printf("dns re-apply failed: %v", err)
					}
					// The endpoint pin points at the old gateway. Without a
					// refresh, handshakes, DoH and the fallback all keep
					// going out the dead interface while everything else
					// follows the new default route.
					if err := s.plat.RepinEndpoint(s.Gateway, s.Iface); err != nil {
						s.log.Printf("endpoint re-pin failed: %v", err)
					}
					s.pinIdx = 0
					s.log.Printf("network changed: interface %s, gateway %s", s.Iface, s.Gateway)
					changed = true
					failures = 0
					s.dnsWedgeSince = time.Time{}
					s.lastDNSRecovery = time.Time{}
					if s.Split != nil {
						s.Split.SetNetwork(split.NetworkKey("", s.Gateway), s.Iface)
					}
					if state == pathWebSocket {
						lastTrial = time.Time{}
					}
				} else if len(routes) > 0 {
					s.log.Printf("routes changed, best still %s via %s (%d candidates)",
						routes[0].Iface, routes[0].Gateway, len(routes))
				}
			}
		}

		if time.Since(lastDNSCheck) >= core.DNSCheckEvery {
			lastDNSCheck = time.Now()
			if err := s.plat.EnsureDNS(s.Iface, s.Gateway); err != nil {
				s.log.Printf("dns check failed: %v", err)
			}
		}

		if err := s.checkDoH(); err != nil {
			return err
		}

		if !s.plat.TunnelUp() {
			if err := s.plat.StartTunnel(); err != nil {
				s.log.Printf("tunnel is down and would not start: %v", err)
				continue
			}
			if state == pathWebSocket {
				if err := s.plat.EnsureEndpoint(s.tcfg.RelayEndpoint()); err != nil {
					s.log.Printf("could not restore the relay endpoint: %v", err)
				}
			}
		}

		switch state {
		case pathUDP:
			if s.probe(8 * time.Second) {
				failures = 0
				continue
			}
			failures++
			s.log.Printf("probe %s failed (%d in a row)", core.AegisTunnelIP, failures)
			// Rotate only on sustained failure: two routes with
			// intermittent loss would otherwise flap the Aegis pin
			// every tick instead of riding it out.
			if failures >= 2 {
				s.rotatePin()
			}
			threshold := 2
			if changed {
				threshold = 1
			}
			if failures < threshold || !s.manageFallback {
				continue
			}
			if err := s.enterWebSocket(ctx); err != nil {
				s.log.Printf("fallback failed: %v", err)
				failures = 0
				continue
			}
			state = pathWebSocket
			lastTrial = time.Now()
			s.log.Printf("udp path is blocked, using the websocket fallback")

		case pathWebSocket:
			if err := s.wst.Ensure(ctx); err != nil {
				s.log.Printf("wstunnel: %v", err)
			}
			if err := s.plat.EnsureEndpoint(s.tcfg.RelayEndpoint()); err != nil {
				s.log.Printf("could not keep the relay endpoint: %v", err)
			}
			s.probeRelay()
			if s.relayFailures >= core.RelayFailThreshold {
				s.log.Printf("relay path failed %d probes in a row; restarting wstunnel and retrying udp early",
					s.relayFailures)
				s.wst.Stop()
				if err := s.wst.Ensure(ctx); err != nil {
					s.log.Printf("wstunnel restart failed: %v", err)
				}
				s.relayFailures = 0
				lastTrial = time.Time{}
			}
			if time.Since(lastTrial) >= core.TrialInterval {
				lastTrial = time.Now()
				if s.trialUDP(ctx) {
					state = pathUDP
					failures = 0
					s.log.Printf("udp path is back")
				}
			}
		}
	}
}

// dnsLoop keeps the resolver applied on DNS-only machines. It mirrors the
// resolver half of loop without touching the tunnel, the fallback, or the
// endpoint pin: without a tunnel there is nothing to move, but DHCP renews
// still need ApplyDNS/EnsureDNS or the machine silently stops using the
// listener.
func (s *Supervisor) dnsLoop(ctx context.Context) error {
	var lastDNSCheck time.Time

	if s.Iface != "" {
		if err := s.plat.EnsureDNS(s.Iface, s.Gateway); err != nil {
			s.log.Printf("dns apply at startup failed: %v", err)
		}
	}

	ticker := time.NewTicker(core.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		health.FlushPendingReport()

		if routes, err := s.plat.DefaultRoutes(); err == nil {
			if !sameRouteSet(routes, s.routes) {
				bestChanged := len(routes) == 0 || len(s.routes) == 0 ||
					routes[0] != s.routes[0]
				s.routes = routes
				if bestChanged && len(routes) > 0 {
					s.Iface, s.Gateway = routes[0].Iface, routes[0].Gateway
					s.resolver.SetGateway(s.Gateway)
					s.resolver.CloseIdle()
					if err := s.plat.ApplyDNS(s.Iface, s.Gateway); err != nil {
						s.log.Printf("dns re-apply failed: %v", err)
					}
					s.pinIdx = 0
					s.log.Printf("network changed: interface %s, gateway %s", s.Iface, s.Gateway)
					s.dnsWedgeSince = time.Time{}
					s.lastDNSRecovery = time.Time{}
				} else if len(routes) > 0 {
					s.log.Printf("routes changed, best still %s via %s (%d candidates)",
						routes[0].Iface, routes[0].Gateway, len(routes))
				}
			}
		}

		if time.Since(lastDNSCheck) >= core.DNSCheckEvery {
			lastDNSCheck = time.Now()
			if err := s.plat.EnsureDNS(s.Iface, s.Gateway); err != nil {
				s.log.Printf("dns check failed: %v", err)
			}
		}

		if err := s.checkDoH(); err != nil {
			return err
		}
	}
}

// dohAction is what checkDoH should do after a streak of failed lookups.
type dohAction int

const (
	dohWait dohAction = iota
	dohReset
	dohGiveUp
)

// dohRecoveryStep is the timing rule for a wedged resolver, kept pure so it
// can be tested without one.
func dohRecoveryStep(now, wedgeSince, lastRecovery time.Time) dohAction {
	if now.Sub(wedgeSince) >= core.DoHWedgeRestartAfter {
		return dohGiveUp
	}
	if lastRecovery.IsZero() || now.Sub(lastRecovery) >= core.DoHRecoverEvery {
		return dohReset
	}
	return dohWait
}

// checkDoH watches the resolver's consecutive failure count. An open listener
// that answers nothing is a whole-stack failure here, not a DNS-only one: the
// relay child resolves through that listener, so a wedged DoH client also
// strands the fallback. Rebuild the client and restart the child; if that does
// not clear after core.DoHWedgeRestartAfter, exit so systemd starts a clean process
// instead of sitting wedged forever.
func (s *Supervisor) checkDoH() error {
	if s.resolver.ConsecutiveFailures() < core.DoHResetAfterFailures {
		s.dnsWedgeSince = time.Time{}
		s.lastDNSRecovery = time.Time{}
		return nil
	}
	now := time.Now()
	if s.dnsWedgeSince.IsZero() {
		s.dnsWedgeSince = now
	}
	switch dohRecoveryStep(now, s.dnsWedgeSince, s.lastDNSRecovery) {
	case dohReset:
		s.log.Printf("doh: %d consecutive lookup failures; rebuilding the client and relay",
			s.resolver.ConsecutiveFailures())
		s.resolver.Reset()
		s.wst.Stop()
		s.relayFailures = 0
		s.lastDNSRecovery = now
	case dohGiveUp:
		return fmt.Errorf("doh wedged for %s despite recovery attempts; exiting for a clean restart",
			now.Sub(s.dnsWedgeSince).Round(time.Second))
	}
	return nil
}

// probeRelay runs one short health probe on the relay path and counts
// consecutive failures. A listening relay port does not prove the WebSocket
// underneath is alive, so the relay gets the same treatment as the direct
// path: short probes, and the caller restarts the child past the threshold.
func (s *Supervisor) probeRelay() bool {
	if s.probe(core.RelayProbeWindow) {
		s.relayFailures = 0
		return true
	}
	s.relayFailures++
	s.log.Printf("probe %s failed on the relay path (%d in a row)", core.AegisTunnelIP, s.relayFailures)
	return false
}

// sameRouteSet reports whether two route lists contain the same entries,
// ignoring order. Used to notice escape paths appearing or vanishing without
// the best route changing.
func sameRouteSet(a, b []platform.Route) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[platform.Route]int, len(a))
	for _, r := range a {
		counts[r]++
	}
	for _, r := range b {
		counts[r]--
		if counts[r] < 0 {
			return false
		}
	}
	return true
}

// refreshRoutes reloads the candidate default routes after a network change
// and pins Aegis traffic to the best one.
func (s *Supervisor) refreshRoutes() {
	routes, err := s.plat.DefaultRoutes()
	if err != nil || len(routes) == 0 {
		return
	}
	s.routes = routes
	s.pinIdx = 0
}

// rotatePin moves the Aegis pin to the next default route after sustained
// probe failure. A default route via a dead interface answers nothing, so
// staying pinned to it would strand the tunnel, DNS and fallback together.
// Single-route machines re-apply the same pin. Always logs: silent rotation
// once hid a real outage from the journal.
func (s *Supervisor) rotatePin() {
	if len(s.routes) == 0 {
		s.refreshRoutes()
	}
	if len(s.routes) == 0 {
		s.log.Printf("route rotation: no default routes, nothing to try")
		return
	}
	next := (s.pinIdx + 1) % len(s.routes)
	if next == s.pinIdx {
		candidate := s.routes[s.pinIdx]
		if err := s.plat.RepinEndpoint(candidate.Gateway, candidate.Iface); err != nil {
			s.log.Printf("route rotation failed: %v", err)
			return
		}
		s.log.Printf("route rotation: only one route, re-pinned %s via %s",
			core.AegisIPv4, candidate.Gateway)
		return
	}
	s.pinIdx = next
	candidate := s.routes[s.pinIdx]
	if err := s.plat.RepinEndpoint(candidate.Gateway, candidate.Iface); err != nil {
		s.log.Printf("route rotation failed: %v", err)
		return
	}
	s.log.Printf("trying next route for aegis traffic: interface %s, gateway %s",
		candidate.Iface, candidate.Gateway)
}

func (s *Supervisor) enterWebSocket(ctx context.Context) error {
	if err := s.wst.Ensure(ctx); err != nil {
		return err
	}
	return s.plat.EnsureEndpoint(s.tcfg.RelayEndpoint())
}

// trialUDP briefly moves the endpoint back to the direct address. If the probe
// answers, the fallback stops; otherwise the relay endpoint is restored.
func (s *Supervisor) trialUDP(ctx context.Context) bool {
	if err := s.plat.EnsureEndpoint(s.tcfg.DirectEndpoint()); err != nil {
		s.log.Printf("udp trial failed to switch: %v", err)
		return false
	}
	if s.probe(6 * time.Second) {
		s.wst.Stop()
		return true
	}
	if err := s.plat.EnsureEndpoint(s.tcfg.RelayEndpoint()); err != nil {
		s.log.Printf("could not return to the relay: %v", err)
	}
	return false
}

func (s *Supervisor) probe(window time.Duration) bool {
	deadline := time.Now().Add(window)
	for {
		ok := s.plat.Ping(core.AegisTunnelIP)
		logx.Debugf("probe %s: %v", core.AegisTunnelIP, ok)
		if ok {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(1500 * time.Millisecond)
	}
}

// noteRestore records a successful re-extraction of the tunneler and gives up
// repeating it once the file is clearly being removed by something else.
func (s *Supervisor) noteRestore(path string) {
	s.restores++
	s.log.Printf("restored the tunneler after it went missing: %s", path)
	if s.restores < tunnelerRestoreLimit {
		return
	}
	s.log.Printf("the tunneler has been removed %d times in a row, so something is deleting it every few seconds. "+
		"Security software is quarantining %s; exclude that directory from real-time scanning, or install a signed build. "+
		"Not retrying for %s.", s.restores, filepath.Dir(path), tunnelerRestorePause)
	s.restorePaused = time.Now().Add(tunnelerRestorePause)
	s.restores = 0
}
