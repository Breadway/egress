package supervisor

import (
	"context"
	"egress/internal/core"
	"egress/internal/doh"
	"egress/internal/health"
	"egress/internal/logx"
	"egress/internal/platform"
	"egress/internal/split"
	"egress/internal/winlog"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sync"
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
	wst      Tunneler
	log      *log.Logger

	manageTunnel   bool
	manageFallback bool
	// preferRelay starts the loop on the WebSocket path because the stored
	// protocol picture says UDP is blocked on this network.
	PreferRelay bool

	// connMu guards the pause flag and the published path. The GUI can pause
	// protection without stopping the service, so the same process keeps
	// serving the local API and can resume on the next request.
	connMu sync.Mutex
	paused bool
	path   string
	// runMu serializes pause/resume with the tunnel start on the loop. Without
	// it a tick that already passed the pause check could restart the tunnel
	// just after the user paused.
	runMu sync.Mutex

	Iface   string
	Gateway string
	// NetworkID optionally resolves the full network identity and the legacy
	// aliases that share its feed. When nil the supervisor falls back to the
	// SSID plus gateway key.
	NetworkID func(iface, gateway string) (string, []string)

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

// Tunneler is the transport that carries WireGuard over the relay. The
// implementation is in-process Go; the interface stays because tests inject a
// fake and the direct path needs no transport at all.
type Tunneler interface {
	Ensure(context.Context) error
	Stop()
}

func New(plat platform.Interface, resolver *doh.Resolver, wst Tunneler, logger *log.Logger, manageTunnel, manageFallback bool) *Supervisor {
	return &Supervisor{
		plat:           plat,
		resolver:       resolver,
		wst:            wst,
		log:            logger,
		manageTunnel:   manageTunnel,
		manageFallback: manageFallback,
		path:           "direct",
	}
}

// SetConnected pauses or resumes protection. Pausing stops the WireGuard
// interface but leaves the resolver, the portal and this API running, so the
// user can reconnect without a service restart. Resuming starts the tunnel;
// the normal loop then re-pins the endpoint and re-applies routes.
func (s *Supervisor) SetConnected(on bool) error {
	// Taking runMu closes the window where a tick has passed its pause check
	// and would otherwise start the tunnel right after StopTunnel.
	s.runMu.Lock()
	defer s.runMu.Unlock()
	s.connMu.Lock()
	was := !s.paused
	s.paused = !on
	s.connMu.Unlock()
	switch {
	case was && !on:
		if s.wst != nil {
			s.wst.Stop()
		}
		return s.plat.StopTunnel()
	case !was && on:
		return s.plat.StartTunnel()
	}
	return nil
}

// Connected reports whether protection is on and the tunnel interface is up.
func (s *Supervisor) Connected() bool {
	s.connMu.Lock()
	paused := s.paused
	s.connMu.Unlock()
	return !paused && s.plat.TunnelUp()
}

// Paused reports the paused flag alone, so callers can tell "user turned it
// off" from "tunnel is still coming up".
func (s *Supervisor) Paused() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.paused
}

// Path is the transport currently carrying the tunnel: "direct" for the UDP
// path, "cloud" for the WebSocket fallback. Both are the same backend; the
// label is what the user sees.
func (s *Supervisor) Path() string {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.path
}

func (s *Supervisor) setPath(path string) {
	s.connMu.Lock()
	s.path = path
	s.connMu.Unlock()
}

// SetFallback allows or forbids the WebSocket fallback at runtime. Turning it
// off while the fallback carries traffic leaves the current path alone; the
// next failure will not enter it.
func (s *Supervisor) SetFallback(on bool) {
	s.connMu.Lock()
	s.manageFallback = on
	s.connMu.Unlock()
}

// Fallback reports whether the fallback is allowed.
func (s *Supervisor) Fallback() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.manageFallback
}

func (s *Supervisor) networkKey() (string, []string) {
	if s.NetworkID != nil {
		if id, aliases := s.NetworkID(s.Iface, s.Gateway); id != "" {
			return id, aliases
		}
	}
	return split.NetworkKey(platform.SSID(s.Iface), s.Gateway), nil
}

// setSplitNetwork applies a resolved network and its aliases to the splitter.
func (s *Supervisor) setSplitNetwork() {
	network, aliases := s.networkKey()
	if s.Split != nil {
		s.Split.SetNetworkAliases(aliases)
		s.Split.SetNetwork(network, s.Iface)
	}
}

func (s *Supervisor) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- s.resolver.Serve(ctx) }()
	if s.Split != nil {
		network, aliases := s.networkKey()
		s.Split.SetNetworkAliases(aliases)
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
	if s.PreferRelay && s.Fallback() {
		if err := s.enterWebSocket(ctx); err != nil {
			s.log.Printf("relay start failed, trying udp: %v", err)
		} else {
			state = pathWebSocket
			s.setPath("cloud")
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
						s.setSplitNetwork()
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

		// The resolver and its DNS setting stay live while paused, so a pause
		// does not silently break ordinary lookups. Only the tunnel and the
		// fallback are owned by this block.
		s.runMu.Lock()
		if s.Paused() {
			if s.plat.TunnelUp() {
				if err := s.plat.StopTunnel(); err != nil {
					s.log.Printf("pause: could not stop the tunnel: %v", err)
				}
			}
			s.runMu.Unlock()
			if s.wst != nil {
				s.wst.Stop()
			}
			continue
		}
		if !s.plat.TunnelUp() {
			if err := s.plat.StartTunnel(); err != nil {
				s.runMu.Unlock()
				s.log.Printf("tunnel is down and would not start: %v", err)
				continue
			}
			if state == pathWebSocket {
				if err := s.plat.EnsureEndpoint(s.tcfg.RelayEndpoint()); err != nil {
					s.log.Printf("could not restore the relay endpoint: %v", err)
				}
			}
		}
		s.runMu.Unlock()

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
			if failures < threshold || !s.Fallback() {
				continue
			}
			if s.Paused() {
				failures = 0
				continue
			}
			if err := s.enterWebSocket(ctx); err != nil {
				s.log.Printf("fallback failed: %v", err)
				failures = 0
				continue
			}
			state = pathWebSocket
			s.setPath("cloud")
			lastTrial = time.Now()
			s.log.Printf("udp path is blocked, using the websocket fallback")

		case pathWebSocket:
			if s.Paused() {
				continue
			}
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
					s.setPath("direct")
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
	winlog.Notify("error", "the tunneler keeps being removed; security software is quarantining "+filepath.Dir(path))
}
