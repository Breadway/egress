package split

import (
	"context"
	"egress/internal/core"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"sync"
	"time"
)

const (
	probeCooldown = 10 * time.Minute
	sweepEvery    = 30 * time.Minute
	sweepMinAge   = 6 * time.Hour
	probeParallel = 6
)

// Controller ties the learned profile to DNS answers and host routes. It
// only acts on names the resolver actually saw, so the profile stays small and
// relevant to what this machine browses.
type Controller struct {
	overrides Overrides
	mu        sync.Mutex
	profile   *Profile
	path      string
	network   string
	iface     string
	log       *log.Logger
	routes    *RouteManager
	tunnelDev string
	probing   map[string]bool
	sem       chan struct{}
	reporter  *splitReporter
	// blockedIPs remembers which addresses were routed for each domain, so an
	// allowed verdict can remove exactly those routes.
	blockedIPs map[string][]string
}

func NewController(network, iface string, routes *RouteManager, logger *log.Logger) *Controller {
	c := &Controller{
		iface:      iface,
		log:        logger,
		routes:     routes,
		probing:    map[string]bool{},
		sem:        make(chan struct{}, probeParallel),
		blockedIPs: map[string][]string{},
	}
	c.overrides = LoadOverrides(ProfileDir())
	c.load(network)
	c.reporter = newSplitReporter(network, ProfileDir(), logger)
	c.reporter.SetMergeFunc(c.mergeFeed)
	c.reporter.SetRefreshFunc(c.refreshSites)
	go c.refreshProtocols()
	return c
}

// SetTunnelDevice names the interface a 403 or 451 comparison is sent over.
// Without it a filtered response stays transient and never routes.
func (c *Controller) SetTunnelDevice(dev string) { c.tunnelDev = dev }

func (c *Controller) load(network string) {
	path := ProfilePath(network)
	profile, err := LoadProfile(path, network)
	if err != nil {
		c.log.Printf("split: could not read %s (%v); starting empty", path, err)
		profile = NewProfile(network)
	}
	c.profile = profile
	c.path = path
	c.network = network
}

// SetNetwork switches to another network's profile and drops the old routes.
func (c *Controller) SetNetwork(network, iface string) {
	c.mu.Lock()
	if network == c.network && iface == c.iface {
		c.mu.Unlock()
		return
	}
	c.iface = iface
	c.load(network)
	c.probing = map[string]bool{}
	c.blockedIPs = map[string][]string{}
	reporter := c.reporter
	c.mu.Unlock()
	reporter.SetNetwork(network)
	go reporter.fetchFeed(context.Background())
	c.routes.Clear()
	c.log.Printf("split: profile %s (routes cleared)", network)
	c.Sweep()
}

// HandleAnswer is called for every DNS answer the listener forwards. Blocked
// names get host routes immediately; unknown names are probed in the
// background so the next visit can be routed.
func (c *Controller) HandleAnswer(domain string, ips []net.IP, ttl time.Duration) {
	if len(ips) == 0 {
		return
	}
	domain = core.NormalizeDomain(domain)
	if domain == "" || probeIgnoredName(domain) {
		return
	}
	now := time.Now()
	c.mu.Lock()
	state := c.profile.State(domain, now)
	if state == StateBlocked {
		c.trackIPsLocked(domain, ips)
		c.mu.Unlock()
		c.routes.Add(ips, ttl, now)
		return
	}
	c.mu.Unlock()

	if state == StateAllowed {
		return
	}
	c.startProbe(domain, probeCooldown)
}

// tunnelStatus fetches the same URL over the tunnel interface. Split mode
// leaves the default route alone, so binding to the tunnel device is how a
// comparison reaches the destination without a full tunnel.
func tunnelStatus(ctx context.Context, domain, dev string) (int, error) {
	res := ProbeConfirmed(ctx, domain, ProbeOptions{Interface: dev, Timeout: ProbeTimeout})
	if res.Status != 0 {
		return res.Status, nil
	}
	if res.Err != nil {
		return 0, res.Err
	}
	return 0, fmt.Errorf("tunnel probe returned no status (%s)", res.State)
}

func (c *Controller) startProbe(domain string, minAge time.Duration) {
	if probeIgnoredName(domain) {
		return
	}
	now := time.Now()
	c.mu.Lock()
	if c.probing[domain] {
		c.mu.Unlock()
		return
	}
	entry := c.profile.Entries[domain]
	if !entry.LastProbe.IsZero() && now.Sub(entry.LastProbe) < minAge {
		c.mu.Unlock()
		return
	}
	c.probing[domain] = true
	c.mu.Unlock()
	go c.probe(domain)
}

func (c *Controller) probe(domain string) {
	c.sem <- struct{}{}
	opts := ProbeOptions{
		Interface: c.iface,
		Timeout:   ProbeTimeout,
	}
	if c.tunnelDev != "" {
		dev := c.tunnelDev
		opts.TunnelStatus = func(ctx context.Context, domain string) (int, error) {
			return tunnelStatus(ctx, domain, dev)
		}
	}
	res := ProbeConfirmed(context.Background(), domain, opts)
	<-c.sem

	now := time.Now()
	c.mu.Lock()
	before := c.profile.State(domain, now)
	if recordProbeOutcome(c.profile, domain, res, now) {
		c.saveLocked()
	}
	blockedNow := c.profile.State(domain, now) == StateBlocked
	allowedNow := c.profile.State(domain, now) == StateAllowed
	var remove []string
	if blockedNow {
		c.trackIPsLocked(domain, parseProbeIPs(res.IPs))
	}
	if allowedNow && before == StateBlocked {
		remove = c.blockedIPs[domain]
		delete(c.blockedIPs, domain)
	}
	delete(c.probing, domain)
	reporter := c.reporter
	c.mu.Unlock()
	if res.State == StateBlocked && before != StateBlocked && reporter != nil {
		reporter.Report(domain, res.Evidence)
	}

	if res.State == StateBlocked || blockedNow {
		c.routes.Add(parseProbeIPs(res.IPs), 0, now)
	}
	if len(remove) > 0 {
		c.routes.Remove(remove)
	}
	log.Printf("split: probe %s", res.String())
}

// Sweep probes seed candidates that have not been tested recently, so common
// sites are classified before the first visit on a new network.
func (c *Controller) Sweep() {
	for _, domain := range SeedCandidates() {
		c.startProbe(core.NormalizeDomain(domain), sweepMinAge)
	}
}

// Run keeps the route table tidy and re-sweeps on a timer.
func (c *Controller) Run(ctx context.Context) {
	clean := time.NewTicker(routeCleanEvery)
	defer clean.Stop()
	sweep := time.NewTicker(sweepEvery)
	defer sweep.Stop()

	go c.reporter.Run(ctx)
	c.Sweep()
	for {
		select {
		case <-ctx.Done():
			return
		case <-clean.C:
			c.routes.Cleanup(time.Now())
		case <-sweep.C:
			c.Sweep()
		}
	}
}

func (c *Controller) trackIPsLocked(domain string, ips []net.IP) {
	if c.blockedIPs == nil {
		c.blockedIPs = map[string][]string{}
	}
	seen := map[string]bool{}
	for _, key := range c.blockedIPs[domain] {
		seen[key] = true
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			key := v4.String()
			if !seen[key] {
				seen[key] = true
				c.blockedIPs[domain] = append(c.blockedIPs[domain], key)
			}
		}
	}
}

func parseProbeIPs(raw []string) []net.IP {
	out := make([]net.IP, 0, len(raw))
	for _, s := range raw {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// mergeFeed installs domains learned by other devices as blocked entries.
// refreshProtocols probes outbound UDP, TCP, DNS and ICMP once per network so
// the shared table carries a protocol picture too. A joining device then knows
// to start on the WebSocket path when UDP is blocked.
func (c *Controller) refreshProtocols() {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	reports := ProbeProtocols(ctx)
	c.reporter.SetProtocols(reports)
	c.mu.Lock()
	changed := 0
	if c.profile.Protocols == nil {
		c.profile.Protocols = map[string]string{}
	}
	for _, r := range reports {
		if r.State == "" || r.State == "unknown" {
			continue
		}
		if c.profile.Protocols[r.Protocol] != r.State {
			c.profile.Protocols[r.Protocol] = r.State
			changed++
		}
	}
	if changed > 0 {
		c.saveLocked()
	}
	c.mu.Unlock()
	if changed > 0 {
		c.log.Printf("split: protocol picture %v", c.profile.Protocols)
	}
}

func (c *Controller) mergeFeed(domains []feedDomain, protocols []feedProtocol) {
	now := time.Now()
	// A domain pinned direct locally is never pulled in by the shared table.
	filtered := domains[:0]
	for _, d := range domains {
		if !c.overrides.Allowed(d.Domain) {
			filtered = append(filtered, d)
		}
	}
	domains = filtered
	c.mu.Lock()
	added, updated := mergeFeedDomains(c.profile, domains, now)
	protos := mergeProtocols(c.profile, protocols)
	if added > 0 || updated > 0 || protos > 0 {
		c.saveLocked()
	}
	c.mu.Unlock()
	if added > 0 {
		c.log.Printf("split: merged %d domains from the shared feed", added)
	}
	if protos > 0 {
		c.log.Printf("split: %.0f protocol observations merged", float64(protos))
	}
	// Do not re-check a domain the operator pinned.
	if len(domains) > 0 {
		c.resolveConflicts(domains)
	}
}

// DomainStatus is one blocked domain as the local page shows it.
type DomainStatus struct {
	Name      string
	Evidence  Evidence
	ServedBy  string
	Unserved  bool
	LastProbe time.Time
}

// StatusSnapshot returns the blocked set for the local page.
func (c *Controller) StatusSnapshot() (network string, domains []DomainStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	network = c.network
	for name, entry := range c.profile.Entries {
		if entry.State != StateBlocked {
			continue
		}
		domains = append(domains, DomainStatus{
			Name:      name,
			Evidence:  entry.Evidence,
			ServedBy:  entry.ServedBy,
			Unserved:  entry.Unserved,
			LastProbe: entry.LastProbe,
		})
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Name < domains[j].Name })
	return network, domains
}

// resolveConflicts answers the server's re-check or verification request for
// a contested domain and shares the answer. The blocked side verifies, the
// allowing side re-checks; either way the answer is a final observation.
func (c *Controller) resolveConflicts(domains []feedDomain) {
	for _, d := range domains {
		if !d.Recheck && !d.Verify {
			continue
		}
		state := c.localState(d.Domain)
		if d.Recheck && state == StateBlocked {
			continue
		}
		if d.Verify && state != StateBlocked {
			continue
		}
		go func(domain string) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			res := ProbeConfirmed(ctx, domain, ProbeOptions{Interface: c.iface, Timeout: ProbeTimeout})
			answer := "allowed"
			if res.State == StateBlocked {
				answer = "blocked"
			}
			evidence := string(res.Evidence)
			if evidence == "" {
				evidence = string(EvidenceFeed)
			}
			c.reporter.ReportFinal(ctx, domain, answer, evidence)
		}(d.Domain)
	}
}

// refreshSites re-verifies blocked sites the server has leased to this device.
// Any observation resets the weekly timer, so the work is a plain probe plus a
// report; it does not need to be the same client that added the entry.
func (c *Controller) refreshSites(due []feedDomain) {
	for _, d := range due {
		if c.overrides.Allowed(d.Domain) {
			continue
		}
		go func(domain string) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			res := ProbeConfirmed(ctx, domain, ProbeOptions{Interface: c.iface, Timeout: ProbeTimeout})
			state := "allowed"
			if res.State == StateBlocked {
				state = "blocked"
			}
			evidence := string(res.Evidence)
			if evidence == "" {
				evidence = string(EvidenceFeed)
			}
			c.reporter.ReportObservation(ctx, domain, state, evidence, false)
			// A refresh that comes back allowed is real evidence: record it
			// locally so this device stops routing the domain.
			now := time.Now()
			c.mu.Lock()
			if recordProbeOutcome(c.profile, domain, res, now) {
				c.saveLocked()
			}
			c.mu.Unlock()
			log.Printf("split: refreshed %s -> %s", domain, state)
		}(d.Domain)
	}
}

func (c *Controller) localState(domain string) DomainState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.profile.State(domain, time.Now())
}

func (c *Controller) saveLocked() {
	if err := c.profile.Save(c.path); err != nil {
		c.log.Printf("split: save profile: %v", err)
	}
}

// BlockedCount is used by diagnose.
func (c *Controller) BlockedCount() (domains, routed int) {
	c.mu.Lock()
	domains = len(c.profile.BlockedDomains(time.Now()))
	c.mu.Unlock()
	return domains, c.routes.Count()
}

// Enabled reports split mode. It is unconditional: routing all traffic
// through the tunnel was removed so a client can never spend the relay's
// bandwidth on ordinary browsing.
func Enabled() bool { return true }

const (
	// Route lifetimes. The DNS TTL is honoured with a floor so short TTLs do
	// not thrash the table, and a cap so a stale entry cannot live for days.
	routeMinTTL     = 10 * time.Minute
	routeMaxTTL     = 6 * time.Hour
	maxSplitRoutes  = 500
	routeCleanEvery = 60 * time.Second
)

// routeRunner runs one `ip route` invocation. Tests replace it.
type routeRunner func(args ...string) error

// RouteManager owns the /32 routes that send learned-blocked destinations into
// wg0. Routes disappear with the interface, but expiry keeps the table small
// between network changes.
type RouteManager struct {
	mu     sync.Mutex
	dev    string
	log    *log.Logger
	run    routeRunner
	routes map[string]time.Time
	order  []string
}

func NewRouteManager(dev string, logger *log.Logger) *RouteManager {
	return &RouteManager{
		dev:    dev,
		log:    logger,
		routes: map[string]time.Time{},
		run:    routeCommands(dev),
	}
}

// routeExec builds one command. Tests replace it to assert the argument
// list without touching the kernel.
var routeExec = exec.Command

// routeCommands returns the host-route commands for the current platform.
// Linux uses iproute2; macOS uses the BSD route(8) syntax. Both are scoped to
// the tunnel interface, so the physical link is untouched. Callers pass the
// verb first: ("replace", ip) or ("del", ip).
func routeCommands(dev string) routeRunner {
	if runtime.GOOS == "darwin" {
		return func(args ...string) error {
			switch args[0] {
			case "replace":
				return routeExec("route", "-n", "add", "-host", args[1], "-interface", dev).Run()
			case "del":
				return routeExec("route", "-n", "delete", "-host", args[1]).Run()
			}
			return fmt.Errorf("unsupported route command %q", args)
		}
	}
	return func(args ...string) error {
		switch args[0] {
		case "replace":
			return routeExec("ip", "route", "replace", args[1], "dev", dev).Run()
		case "del":
			return routeExec("ip", "route", "del", args[1], "dev", dev).Run()
		}
		return fmt.Errorf("unsupported route command %q", args)
	}
}

func (m *RouteManager) Add(ips []net.IP, ttl time.Duration, now time.Time) {
	if m == nil || m.dev == "" {
		return
	}
	if ttl < routeMinTTL {
		ttl = routeMinTTL
	}
	if ttl > routeMaxTTL {
		ttl = routeMaxTTL
	}
	expiry := now.Add(ttl)

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		key := v4.String()
		if _, ok := m.routes[key]; ok {
			m.routes[key] = expiry
			continue
		}
		if len(m.routes) >= maxSplitRoutes && len(m.order) > 0 {
			oldest := m.order[0]
			m.order = m.order[1:]
			delete(m.routes, oldest)
			_ = m.run("del", oldest)
		}
		if err := m.run("replace", key); err != nil {
			log.Printf("split: route add %s failed: %v", key, err)
			continue
		}
		m.routes[key] = expiry
		m.order = append(m.order, key)
		log.Printf("split: routed %s via %s until %s", key, m.dev, expiry.Format(time.RFC3339))
	}
}

func (m *RouteManager) Cleanup(now time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.order[:0]
	for _, key := range m.order {
		expiry, ok := m.routes[key]
		if !ok {
			continue
		}
		if now.After(expiry) {
			_ = m.run("del", key)
			delete(m.routes, key)
			continue
		}
		kept = append(kept, key)
	}
	m.order = kept
}

// Remove deletes specific host routes, used when a domain becomes allowed
// again.
func (m *RouteManager) Remove(keys []string) {
	if m == nil || len(keys) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, key := range keys {
		if _, ok := m.routes[key]; !ok {
			continue
		}
		_ = m.run("del", key)
		delete(m.routes, key)
	}
}

// Clear removes every route this manager added, for a network change.
func (m *RouteManager) Clear() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, key := range m.order {
		_ = m.run("del", key)
	}
	m.routes = map[string]time.Time{}
	m.order = nil
}

func (m *RouteManager) Count() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.routes)
}

// seedCandidates are the domains worth testing on a new network. They are not
// assumed blocked: the sweep probes each one directly and records the result in
// the network profile. The list comes from measurements on Australian school
// networks in November 2026, plus the obvious redirect targets.
var seedCandidates = []string{
	// Social and messaging
	"discord.com",
	"x.com",
	"twitter.com",
	"instagram.com",
	"facebook.com",
	"www.facebook.com",
	"tiktok.com",
	"www.tiktok.com",
	"reddit.com",
	"www.reddit.com",
	"old.reddit.com",
	// Video and streaming
	"netflix.com",
	"www.netflix.com",
	"twitch.tv",
	"www.twitch.tv",
	"youtube.com",
	"www.youtube.com",
	// Music
	"spotify.com",
	"open.spotify.com",
	// Gaming
	"store.steampowered.com",
	"steamcommunity.com",
	"poki.com",
	"www.poki.com",
	"roblox.com",
	"www.roblox.com",
	// Commonly allowed, useful as controls
	"google.com",
	"www.google.com",
	"github.com",
	"chatgpt.com",
}

// SeedCandidates returns a copy so callers cannot mutate the seed.
func SeedCandidates() []string {
	out := make([]string, len(seedCandidates))
	copy(out, seedCandidates)
	return out
}
