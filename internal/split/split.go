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
	"strings"
	"sync"
	"sync/atomic"
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
	// exits are the direct exits published with the feed.
	exits []DirectExit
	// shareReports controls outbound learning only. The feed is still read, so
	// a device that stops sharing keeps receiving the circle's blocks.
	shareReports atomic.Bool
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
	c.shareReports.Store(true)
	c.load(network)
	// Clear routes left by a previous process. The supervisor calls SetNetwork
	// right after this with the same network, which returns early, so startup
	// is the only chance to remove kernel routes nobody tracks yet.
	c.routes.Reset()
	c.reporter = newSplitReporter(network, ProfileDir(), logger)
	c.reporter.SetMergeFunc(c.mergeFeed)
	c.reporter.SetRefreshFunc(c.refreshSites)
	go c.refreshProtocols()
	return c
}

// SetShareReports enables or disables outbound learning. Incoming feed data
// and local probing continue either way.
func (c *Controller) SetShareReports(on bool) { c.shareReports.Store(on) }

// SetExitsHandler receives the direct exits published with the feed, and gets
// the current list immediately so a handler installed after the first fetch
// still sees it.
func (c *Controller) SetExitsHandler(fn func([]DirectExit)) {
	c.reporter.SetExitsFunc(func(list []DirectExit) {
		c.mu.Lock()
		c.exits = append([]DirectExit(nil), list...)
		c.mu.Unlock()
		if fn != nil {
			fn(list)
		}
	})
	c.mu.Lock()
	current := append([]DirectExit(nil), c.exits...)
	c.mu.Unlock()
	if fn != nil && len(current) > 0 {
		fn(current)
	}
}

// Exits returns the direct exits the feed last published.
func (c *Controller) Exits() []DirectExit {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]DirectExit(nil), c.exits...)
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
	c.routes.Reset()
	c.log.Printf("split: profile %s (stale tunnel routes cleared)", network)
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
	// A local override beats the profile and the probe. split-block.txt is
	// what makes "force this through the tunnel" possible without a release,
	// and it has to work for the controller, not only for the proxy.
	if state, ok := c.overrides.Forced(domain); ok {
		if state == StateBlocked {
			now := time.Now()
			c.mu.Lock()
			c.trackIPsLocked(domain, ips)
			c.mu.Unlock()
			c.routes.Add(ips, ttl, now)
		}
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

// Retry queues one verification attempt for a known domain. The GUI's retry
// button uses it when a site could not be served.
func (c *Controller) Retry(domain string) bool {
	c.mu.Lock()
	_, known := c.profile.Entries[domain]
	c.mu.Unlock()
	if !known {
		return false
	}
	c.startProbe(domain, 0)
	return true
}

// Observe queues a first probe for a site the user reported. The result is
// recorded like any other observation, so a blocked report joins the profile
// and an allowed one does not.
func (c *Controller) Observe(domain string) {
	c.startProbe(domain, 0)
}

func (c *Controller) probe(domain string) {
	c.sem <- struct{}{}
	opts := ProbeOptions{
		Interface: c.iface,
		Timeout:   ProbeTimeout,
		Resolve:   core.LookupHost,
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
	// Only a verdict strong enough to mean a filter is shared. A TLS stall is
	// also what a host without an HTTPS service looks like: this profile holds
	// 0.arch.pool.ntp.org and CDN hosts for that reason, and routing those into
	// the tunnel on every device would be worse than learning them locally.
	if res.State == StateBlocked && before != StateBlocked && reporter != nil &&
		c.shareReports.Load() && strongBlockEvidence(res.Evidence) {
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

// strongBlockEvidence reports whether a block verdict is specific enough to
// share with other devices. A TCP or TLS stall is not: dead hosts and services
// without HTTPS produce the same result as a filter. A rejected status, a
// substituted certificate or an identified block page can only come from
// something acting on the path.
func strongBlockEvidence(e Evidence) bool {
	switch e {
	case EvidenceIPRejected, EvidenceCertSubstitution, EvidenceFeed:
		return true
	}
	return strings.HasPrefix(string(e), string(EvidenceInterceptPage))
}

type sharedBlock struct {
	domain   string
	evidence Evidence
}

// shareableBlocks selects the local blocked set worth sharing, deterministically.
func shareableBlocks(p *Profile, overrides Overrides) []sharedBlock {
	out := make([]sharedBlock, 0, len(p.Entries))
	for domain, entry := range p.Entries {
		if entry.State != StateBlocked || !strongBlockEvidence(entry.Evidence) {
			continue
		}
		if overrides.Allowed(domain) {
			continue
		}
		out = append(out, sharedBlock{domain: domain, evidence: entry.Evidence})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].domain < out[j].domain })
	return out
}

// shareKnownBlocks sends the blocked set this device already holds, in batches,
// so the shared table catches up with reality after a failed report or an
// upgrade that started sharing later.
func (c *Controller) shareKnownBlocks(ctx context.Context) {
	c.mu.Lock()
	blocks := shareableBlocks(c.profile, c.overrides)
	network := c.network
	reporter := c.reporter
	c.mu.Unlock()
	if reporter == nil || len(blocks) == 0 || !c.shareReports.Load() {
		return
	}
	shared := 0
	for start := 0; start < len(blocks); start += splitReportBatch {
		end := start + splitReportBatch
		if end > len(blocks) {
			end = len(blocks)
		}
		for _, b := range blocks[start:end] {
			reporter.Report(b.domain, b.evidence)
		}
		if err := reporter.flush(ctx); err != nil {
			c.log.Printf("split: shared %d of %d known blocks, then stopped: %v", shared, len(blocks), err)
			return
		}
		shared += end - start
		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
	c.log.Printf("split: shared %d known blocks for %s", shared, network)
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
	// The transition above is edge triggered. A report that failed once, or a
	// verdict from before the share existed, otherwise stays on this device
	// forever, and the shared table never converges with what the machine
	// knows. Replaying the blocked set on start is safe because the server
	// merges observations idempotently.
	go c.shareKnownBlocks(ctx)
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
			if c.shareReports.Load() {
				c.reporter.ReportFinal(ctx, domain, answer, evidence)
			}
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
			if c.shareReports.Load() {
				c.reporter.ReportObservation(ctx, domain, state, evidence, false)
			}
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
	mu  sync.Mutex
	dev string
	log *log.Logger
	run routeRunner
	// list reads the kernel's routes. Injected so tests never touch the real
	// tunnel; nil means "no listing", which is what a test fake wants.
	list   func(dev string) []string
	routes map[string]time.Time
	order  []string
	// onChange is told the routed set whenever it changes. Windows needs this:
	// WireGuard only carries destinations named in the peer's AllowedIPs, so a
	// route the driver does not know about blackholes silently.
	onChange func([]string)
}

func NewRouteManager(dev string, logger *log.Logger) *RouteManager {
	return &RouteManager{
		dev:    dev,
		log:    logger,
		routes: map[string]time.Time{},
		run:    routeCommands(dev),
		list:   kernelRoutesOn,
	}
}

// Reset removes every route on the tunnel device that this process did not
// add. After a restart or a network change the kernel still holds the previous
// network's routes, and the in-memory map cannot see them; without this they
// accumulate and keep sending traffic through the tunnel.
func (m *RouteManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	if m.list != nil {
		for _, prefix := range m.list(m.dev) {
			if err := m.run("del", prefix); err == nil {
				removed++
			}
		}
	}
	m.routes = map[string]time.Time{}
	m.order = nil
	m.notifyLocked()
	if removed > 0 {
		log.Printf("split: cleared %d stale tunnel routes", removed)
	}
}

// kernelRoutesOn lists the destination routes the kernel holds on dev.
func kernelRoutesOn(dev string) []string {
	if dev == "" {
		return nil
	}
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-NetRoute -InterfaceAlias '"+dev+"' -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.DestinationPrefix }").Output()
		if err != nil {
			return nil
		}
		return parseTunnelRoutes(string(out))
	case "linux":
		out, err := exec.Command("ip", "route", "show", "dev", dev).Output()
		if err != nil {
			return nil
		}
		return parseTunnelRoutes(string(out))
	}
	return nil
}

// parseTunnelRoutes returns the destinations of the routes on the tunnel,
// excluding the tunnel subnet itself, which the tunnel needs.
func parseTunnelRoutes(output string) []string {
	var out []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		dst := fields[0]
		if dst == "10.88.0.0/24" || dst == "default" {
			continue
		}
		out = append(out, dst)
	}
	return out
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
	if runtime.GOOS == "windows" {
		return func(args ...string) error {
			// Reset replays prefixes read back from the routing table, which
			// already carry /32; Add passes a bare address. Accept both, or
			// cleanup asks for 1.2.3.4/32/32 and silently leaves the route.
			prefix := args[1]
			if !strings.Contains(prefix, "/") {
				prefix += "/32"
			}
			switch args[0] {
			case "replace":
				return routeExec("powershell", "-NoProfile", "-NonInteractive", "-Command",
					"New-NetRoute -DestinationPrefix '"+prefix+"' -InterfaceAlias '"+dev+"' -PolicyStore ActiveStore -ErrorAction Stop | Out-Null").Run()
			case "del":
				return routeExec("powershell", "-NoProfile", "-NonInteractive", "-Command",
					"Remove-NetRoute -DestinationPrefix '"+prefix+"' -Confirm:$false -ErrorAction SilentlyContinue | Out-Null").Run()
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

// OnChange registers a callback for routed-set changes.
func (m *RouteManager) OnChange(fn func([]string)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = fn
}

// notifyLocked hands the current routed set to the callback. The caller holds
// the lock; the callback is expected to be quick (one wg set).
func (m *RouteManager) notifyLocked() {
	if m.onChange == nil {
		return
	}
	out := make([]string, 0, len(m.order))
	for _, key := range m.order {
		if _, ok := m.routes[key]; ok {
			out = append(out, key)
		}
	}
	m.onChange(out)
}

// Prefixes reports the current routed set, for callers that need to resend it.
func (m *RouteManager) Prefixes() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.order))
	for _, key := range m.order {
		if _, ok := m.routes[key]; ok {
			out = append(out, key)
		}
	}
	return out
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
	m.notifyLocked()
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
	if len(kept) != len(m.order) {
		m.order = kept
		m.notifyLocked()
		return
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
	m.notifyLocked()
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
	m.notifyLocked()
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
