package egress

import (
	"context"
	"egress/internal/doh"
	"egress/internal/split"
	"fmt"
	"log"
	"net"
	"time"
)

type pathState int

const (
	pathUDP pathState = iota
	pathWebSocket
)

// supervisor keeps the DoH resolver running and moves the WireGuard exit
// between the direct UDP path and the WebSocket fallback.
//
// The health signal is a probe of Aegis's tunnel address, not the WireGuard
// handshake: while the fallback carries traffic the handshake stays fresh
// through it, so handshake age cannot tell a working UDP path from a rescued
// one.
type supervisor struct {
	plat     platform
	resolver *doh.Resolver
	tcfg     tunnelConfig
	wst      *wstunnelProc
	log      *log.Logger

	manageTunnel   bool
	manageFallback bool
	// preferRelay starts the loop on the WebSocket path because the stored
	// protocol picture says UDP is blocked on this network.
	preferRelay bool

	iface   string
	gateway string

	// Candidate default routes, best first, with the index currently
	// pinned. On sustained probe failure the pin walks the list so one dead
	// interface cannot strand the tunnel, DNS and fallback together.
	routes []Route
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
	split *split.Controller
}

func newSupervisor(plat platform, resolver *doh.Resolver, wst *wstunnelProc, logger *log.Logger, manageTunnel, manageFallback bool) *supervisor {
	return &supervisor{
		plat:           plat,
		resolver:       resolver,
		wst:            wst,
		log:            logger,
		manageTunnel:   manageTunnel,
		manageFallback: manageFallback,
	}
}

func (s *supervisor) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- s.resolver.Serve(ctx) }()
	if s.split != nil {
		network := split.NetworkKey("", s.gateway)
		s.split.SetNetwork(network, s.iface)
		s.resolver.SetObserver(func(domain string, ips []net.IP, ttl time.Duration) {
			s.split.HandleAnswer(domain, ips, ttl)
		})
		go s.split.Run(ctx)
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

func (s *supervisor) loop(ctx context.Context) error {
	state := pathUDP
	failures := 0
	if s.preferRelay && s.manageFallback {
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
	// restores DNS without waiting a full dnsCheckEvery.
	if s.iface != "" {
		if err := s.plat.EnsureDNS(s.iface, s.gateway); err != nil {
			s.log.Printf("dns apply at startup failed: %v", err)
		}
	}

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		debugf("tick: state=%d failures=%d tunnel=%v iface=%s gateway=%s",
			state, failures, s.plat.TunnelUp(), s.iface, s.gateway)

		// changed tracks a fresh route flip for this tick only. The first
		// probe after a flip fails over immediately instead of waiting out
		// another full round, because a flip usually means the old path is
		// gone, not merely lossy.
		changed := false

		// Deliver a spooled install report from a previous failed run, if any.
		// Cheap when there is nothing to send: one stat call.
		flushPendingReport()

		// Track the whole default-route set, not just the best route. A new
		// escape path can appear (or vanish) without the best route
		// changing, and a best route can go dead while staying selected.
		if routes, err := s.plat.DefaultRoutes(); err == nil {
			if !sameRouteSet(routes, s.routes) {
				bestChanged := len(routes) == 0 || len(s.routes) == 0 ||
					routes[0] != s.routes[0]
				s.routes = routes
				if bestChanged && len(routes) > 0 {
					s.iface, s.gateway = routes[0].Iface, routes[0].Gateway
					s.resolver.SetGateway(s.gateway)
					// Drop pooled connections bound to the old interface.
					s.resolver.CloseIdle()
					if err := s.plat.ApplyDNS(s.iface, s.gateway); err != nil {
						s.log.Printf("dns re-apply failed: %v", err)
					}
					// The endpoint pin points at the old gateway. Without a
					// refresh, handshakes, DoH and the fallback all keep
					// going out the dead interface while everything else
					// follows the new default route.
					if err := s.plat.RepinEndpoint(s.gateway, s.iface); err != nil {
						s.log.Printf("endpoint re-pin failed: %v", err)
					}
					s.pinIdx = 0
					s.log.Printf("network changed: interface %s, gateway %s", s.iface, s.gateway)
					changed = true
					failures = 0
					s.dnsWedgeSince = time.Time{}
					s.lastDNSRecovery = time.Time{}
					if s.split != nil {
						s.split.SetNetwork(split.NetworkKey("", s.gateway), s.iface)
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

		if time.Since(lastDNSCheck) >= dnsCheckEvery {
			lastDNSCheck = time.Now()
			if err := s.plat.EnsureDNS(s.iface, s.gateway); err != nil {
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
			s.log.Printf("probe %s failed (%d in a row)", aegisTunnelIP, failures)
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
			if s.relayFailures >= relayFailThreshold {
				s.log.Printf("relay path failed %d probes in a row; restarting wstunnel and retrying udp early",
					s.relayFailures)
				s.wst.Stop()
				if err := s.wst.Ensure(ctx); err != nil {
					s.log.Printf("wstunnel restart failed: %v", err)
				}
				s.relayFailures = 0
				lastTrial = time.Time{}
			}
			if time.Since(lastTrial) >= trialInterval {
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
func (s *supervisor) dnsLoop(ctx context.Context) error {
	var lastDNSCheck time.Time

	if s.iface != "" {
		if err := s.plat.EnsureDNS(s.iface, s.gateway); err != nil {
			s.log.Printf("dns apply at startup failed: %v", err)
		}
	}

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		flushPendingReport()

		if routes, err := s.plat.DefaultRoutes(); err == nil {
			if !sameRouteSet(routes, s.routes) {
				bestChanged := len(routes) == 0 || len(s.routes) == 0 ||
					routes[0] != s.routes[0]
				s.routes = routes
				if bestChanged && len(routes) > 0 {
					s.iface, s.gateway = routes[0].Iface, routes[0].Gateway
					s.resolver.SetGateway(s.gateway)
					s.resolver.CloseIdle()
					if err := s.plat.ApplyDNS(s.iface, s.gateway); err != nil {
						s.log.Printf("dns re-apply failed: %v", err)
					}
					s.pinIdx = 0
					s.log.Printf("network changed: interface %s, gateway %s", s.iface, s.gateway)
					s.dnsWedgeSince = time.Time{}
					s.lastDNSRecovery = time.Time{}
				} else if len(routes) > 0 {
					s.log.Printf("routes changed, best still %s via %s (%d candidates)",
						routes[0].Iface, routes[0].Gateway, len(routes))
				}
			}
		}

		if time.Since(lastDNSCheck) >= dnsCheckEvery {
			lastDNSCheck = time.Now()
			if err := s.plat.EnsureDNS(s.iface, s.gateway); err != nil {
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
	if now.Sub(wedgeSince) >= dohWedgeRestartAfter {
		return dohGiveUp
	}
	if lastRecovery.IsZero() || now.Sub(lastRecovery) >= dohRecoverEvery {
		return dohReset
	}
	return dohWait
}

// checkDoH watches the resolver's consecutive failure count. An open listener
// that answers nothing is a whole-stack failure here, not a DNS-only one: the
// relay child resolves through that listener, so a wedged DoH client also
// strands the fallback. Rebuild the client and restart the child; if that does
// not clear after dohWedgeRestartAfter, exit so systemd starts a clean process
// instead of sitting wedged forever.
func (s *supervisor) checkDoH() error {
	if s.resolver.ConsecutiveFailures() < dohResetAfterFailures {
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
func (s *supervisor) probeRelay() bool {
	if s.probe(relayProbeWindow) {
		s.relayFailures = 0
		return true
	}
	s.relayFailures++
	s.log.Printf("probe %s failed on the relay path (%d in a row)", aegisTunnelIP, s.relayFailures)
	return false
}

// sameRouteSet reports whether two route lists contain the same entries,
// ignoring order. Used to notice escape paths appearing or vanishing without
// the best route changing.
func sameRouteSet(a, b []Route) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[Route]int, len(a))
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
func (s *supervisor) refreshRoutes() {
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
func (s *supervisor) rotatePin() {
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
			aegisIPv4, candidate.Gateway)
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

func (s *supervisor) enterWebSocket(ctx context.Context) error {
	if err := s.wst.Ensure(ctx); err != nil {
		return err
	}
	return s.plat.EnsureEndpoint(s.tcfg.RelayEndpoint())
}

// trialUDP briefly moves the endpoint back to the direct address. If the probe
// answers, the fallback stops; otherwise the relay endpoint is restored.
func (s *supervisor) trialUDP(ctx context.Context) bool {
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

func (s *supervisor) probe(window time.Duration) bool {
	deadline := time.Now().Add(window)
	for {
		ok := s.plat.Ping(aegisTunnelIP)
		debugf("probe %s: %v", aegisTunnelIP, ok)
		if ok {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(1500 * time.Millisecond)
	}
}
