package split

import (
	"context"
	"egress/internal/core"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
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
	mu       sync.Mutex
	profile  *Profile
	path     string
	network  string
	iface    string
	log      *log.Logger
	routes   *RouteManager
	probing  map[string]bool
	sem      chan struct{}
	reporter *splitReporter
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
	c.load(network)
	c.reporter = newSplitReporter(network, ProfileDir(), logger)
	c.reporter.SetMergeFunc(c.mergeFeed)
	return c
}

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
	res := ProbeConfirmed(context.Background(), domain, ProbeOptions{
		Interface: c.iface,
		Timeout:   ProbeTimeout,
	})
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
func (c *Controller) mergeFeed(domains []feedDomain) {
	now := time.Now()
	c.mu.Lock()
	added := mergeFeedDomains(c.profile, domains, now)
	if added > 0 {
		c.saveLocked()
	}
	c.mu.Unlock()
	if added > 0 {
		c.log.Printf("split: merged %d domains from the shared feed", added)
	}
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

// routeCommands returns the host-route commands for the current platform.
// Linux uses iproute2; macOS uses the BSD route(8) syntax. Both are scoped to
// the tunnel interface, so the physical link is untouched.
func routeCommands(dev string) routeRunner {
	if runtime.GOOS == "darwin" {
		return func(args ...string) error {
			switch args[0] {
			case "route":
				switch args[1] {
				case "replace":
					return exec.Command("route", "-n", "add", "-host", args[2], "-interface", dev).Run()
				case "del":
					return exec.Command("route", "-n", "delete", "-host", args[2]).Run()
				}
			}
			return fmt.Errorf("unsupported route command %q", args)
		}
	}
	return func(args ...string) error {
		return exec.Command("ip", args...).Run()
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
