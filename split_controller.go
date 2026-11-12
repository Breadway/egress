package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

const (
	probeCooldown = 10 * time.Minute
	sweepEvery    = 30 * time.Minute
	sweepMinAge   = 6 * time.Hour
	probeParallel = 6
)

// splitController ties the learned profile to DNS answers and host routes. It
// only acts on names the resolver actually saw, so the profile stays small and
// relevant to what this machine browses.
type splitController struct {
	mu       sync.Mutex
	profile  *Profile
	path     string
	network  string
	iface    string
	log      *log.Logger
	routes   *routeManager
	probing  map[string]bool
	sem      chan struct{}
	reporter *splitReporter
	// blockedIPs remembers which addresses were routed for each domain, so an
	// allowed verdict can remove exactly those routes.
	blockedIPs map[string][]string
}

func newSplitController(network, iface string, routes *routeManager, logger *log.Logger) *splitController {
	c := &splitController{
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

func (c *splitController) load(network string) {
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
func (c *splitController) SetNetwork(network, iface string) {
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
func (c *splitController) HandleAnswer(domain string, ips []net.IP, ttl time.Duration) {
	if len(ips) == 0 {
		return
	}
	domain = NormalizeDomain(domain)
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

func (c *splitController) startProbe(domain string, minAge time.Duration) {
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

func (c *splitController) probe(domain string) {
	c.sem <- struct{}{}
	res := ProbeConfirmed(context.Background(), domain, ProbeOptions{
		Interface: c.iface,
		Timeout:   probeTimeout,
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
	debugf("split: probe %s", res.String())
}

// Sweep probes seed candidates that have not been tested recently, so common
// sites are classified before the first visit on a new network.
func (c *splitController) Sweep() {
	for _, domain := range SeedCandidates() {
		c.startProbe(NormalizeDomain(domain), sweepMinAge)
	}
}

// Run keeps the route table tidy and re-sweeps on a timer.
func (c *splitController) Run(ctx context.Context) {
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

func (c *splitController) trackIPsLocked(domain string, ips []net.IP) {
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
func (c *splitController) mergeFeed(domains []feedDomain) {
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

func (c *splitController) saveLocked() {
	if err := c.profile.Save(c.path); err != nil {
		c.log.Printf("split: save profile: %v", err)
	}
}

// BlockedCount is used by diagnose.
func (c *splitController) BlockedCount() (domains, routed int) {
	c.mu.Lock()
	domains = len(c.profile.BlockedDomains(time.Now()))
	c.mu.Unlock()
	return domains, c.routes.Count()
}
