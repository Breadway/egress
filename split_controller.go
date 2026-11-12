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
	mu      sync.Mutex
	profile *Profile
	path    string
	network string
	iface   string
	log     *log.Logger
	routes  *routeManager
	probing map[string]bool
	sem     chan struct{}
}

func newSplitController(network, iface string, routes *routeManager, logger *log.Logger) *splitController {
	c := &splitController{
		iface:   iface,
		log:     logger,
		routes:  routes,
		probing: map[string]bool{},
		sem:     make(chan struct{}, probeParallel),
	}
	c.load(network)
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
	c.mu.Unlock()
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
	if domain == "" {
		return
	}
	now := time.Now()
	c.mu.Lock()
	state := c.profile.State(domain, now)
	c.mu.Unlock()

	if state == StateBlocked {
		c.routes.Add(ips, ttl, now)
		return
	}
	if state == StateAllowed {
		return
	}
	c.startProbe(domain, probeCooldown)
}

func (c *splitController) startProbe(domain string, minAge time.Duration) {
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
	res := ProbeDomain(context.Background(), domain, ProbeOptions{
		Interface: c.iface,
		Timeout:   probeTimeout,
	})
	<-c.sem

	now := time.Now()
	c.mu.Lock()
	switch res.State {
	case StateBlocked:
		// The classifier only reports blocked for a definite stall or a
		// certificate substitution, and for 403 direct with 200 through the
		// tunnel. Record it as a full streak.
		c.profile.RecordProbe(domain, res.Evidence, true, now)
		c.profile.RecordProbe(domain, res.Evidence, true, now)
		c.saveLocked()
	case StateAllowed:
		c.profile.RecordProbe(domain, EvidenceNone, false, now)
		c.saveLocked()
	}
	delete(c.probing, domain)
	c.mu.Unlock()

	if res.State == StateBlocked {
		ips := make([]net.IP, 0, len(res.IPs))
		for _, raw := range res.IPs {
			if ip := net.ParseIP(raw); ip != nil {
				ips = append(ips, ip)
			}
		}
		c.routes.Add(ips, 0, now)
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
