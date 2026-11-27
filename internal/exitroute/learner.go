package exitroute

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// CloudMark selects the routing table the cloud probe leaves through, so a
	// learned assignment cannot make the cloud check follow an exit.
	CloudMark = 0x44

	cloudTable = 812

	probeUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

// Options configures the learner.
type Options struct {
	FeedDir      string
	ExtraDomains string
	StatePath    string
	StatusPath   string
	RegistryPath string
	Interval     time.Duration
	TTL          time.Duration
	HealthWindow time.Duration
	// RetryUnserved is how long a name no exit could serve is left alone
	// before every exit is tried again. The cloud is still checked each cycle.
	RetryUnserved time.Duration
	Dev           string
	CloudDev      string
	Limit         int
	Concurrency   int
	Timeout       time.Duration
	DryRun        bool
	Logf          func(format string, args ...any)
}

// Summary is one cycle's outcome.
type Summary struct {
	Candidates int
	Checked    int
	Served     int
	Unserved   int
	Changed    int
}

// Learner compares sites over the cloud exit and every enrolled exit, and
// keeps the routes in step with the result.
type Learner struct {
	opts    Options
	reg     Registry
	exits   []Exit
	state   State
	applied map[string]bool   // prefix -> route installed
	lists   map[string]string // exit id -> allowed-ips applied
	blocked map[string]map[string]bool

	// wasHealthy tracks exit health between cycles, so an exit coming back
	// clears the unserved backoff instead of waiting it out.
	wasHealthy   map[string]bool
	exitsChanged bool

	// Injected in tests.
	probeFn    func(ctx context.Context, domain, ip string, mark int) ProbeResult
	setAllowed func(dev, pub, list string) error
	addRouteFn func(prefix string) error
	delRouteFn func(prefix string) error
}

// New returns a learner with the given options and its saved state.
func New(opts Options) (*Learner, error) {
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Minute
	}
	if opts.TTL <= 0 {
		opts.TTL = 24 * time.Hour
	}
	if opts.HealthWindow <= 0 {
		opts.HealthWindow = 5 * time.Minute
	}
	if opts.RetryUnserved <= 0 {
		opts.RetryUnserved = 30 * time.Minute
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 12 * time.Second
	}
	if opts.Dev == "" {
		opts.Dev = "wg0"
	}
	if opts.CloudDev == "" {
		opts.CloudDev = "ens3"
	}
	if opts.Limit <= 0 {
		opts.Limit = 800
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	state, err := LoadState(opts.StatePath)
	if err != nil {
		return nil, err
	}
	l := &Learner{
		opts:    opts,
		state:   state,
		applied: map[string]bool{},
		lists:   map[string]string{},
	}
	l.probeFn = l.probe
	l.setAllowed = func(dev, pub, list string) error {
		return run("wg", "set", dev, "peer", pub, "allowed-ips", list)
	}
	l.addRouteFn = func(prefix string) error {
		return run("ip", "route", "replace", prefix, "dev", opts.Dev)
	}
	l.delRouteFn = func(prefix string) error { return run("ip", "route", "del", prefix) }
	return l, nil
}

// Run loops until the context is cancelled.
func (l *Learner) Run(ctx context.Context) error {
	ticker := time.NewTicker(l.opts.Interval)
	defer ticker.Stop()
	for {
		sum, err := l.RunOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			l.opts.Logf("exit: cycle failed: %v", err)
		} else {
			l.opts.Logf("exit: checked %d of %d blocked names, %d served by an exit, %d unserved, %d changes",
				sum.Checked, sum.Candidates, sum.Served, sum.Unserved, sum.Changed)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

type resolved struct {
	domain   string
	prefixes []string
	ips      []string
	cloud    ProbeResult
	ok       bool
}

// RunOnce performs one learning cycle.
func (l *Learner) RunOnce(ctx context.Context) (Summary, error) {
	var sum Summary
	now := time.Now()

	l.blocked = nil
	reg, err := LoadRegistry(l.opts.RegistryPath)
	if err != nil {
		return sum, fmt.Errorf("read the exit registry: %w", err)
	}
	l.reg = reg
	l.exits = EnabledExits(reg)

	if err := l.ensureCloudRouting(); err != nil {
		return sum, err
	}

	candidates, err := l.candidates()
	if err != nil {
		return sum, err
	}
	sum.Candidates = len(candidates)

	// Probe the cloud for every candidate first. This is independent of any
	// assignment because it is marked to leave through the physical link.
	results := make([]resolved, len(candidates))
	sem := make(chan struct{}, l.opts.Concurrency)
	var wg sync.WaitGroup
	for i, candidate := range candidates {
		i, domain := i, candidate.Domain
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			results[i] = l.resolveAndProbeCloud(ctx, domain)
		}()
	}
	wg.Wait()

	handshakes := l.handshakes()
	l.noteExitHealth(handshakes, now)
	if !l.opts.DryRun {
		// Anything already routed over the tunnel is ours; starting from the
		// kernel means a stale route can be removed and a dropped one restored.
		l.applied = l.kernelRoutes()
	}
	l.syncRoutes()

	seen := make(map[string]bool, len(results))
	previous := make(map[string]Site, len(l.state.Sites))
	for domain, site := range l.state.Sites {
		previous[domain] = site
	}

	for _, r := range results {
		if !r.ok {
			// A resolution failure says nothing about the site; keep what we
			// knew rather than flapping an assignment.
			if prev, ok := l.state.Sites[r.domain]; ok {
				seen[r.domain] = true
				_ = prev
			}
			continue
		}
		seen[r.domain] = true
		sum.Checked++
		site := l.decide(ctx, r, handshakes, now)
		if prev, ok := previous[r.domain]; !ok || prev.State != site.State || prev.Exit != site.Exit {
			sum.Changed++
			l.opts.Logf("exit: %s is %s%s (cloud %d%s)", site.Domain, site.State,
				exitSuffix(site), site.Cloud, errSuffix(site.CloudErr))
		}
		l.state.Sites[r.domain] = site
	}

	l.prune(seen, now)
	l.syncRoutes()
	l.state.Updated = now.UTC()

	status := l.buildStatus(now, handshakes)
	if !l.opts.DryRun {
		if err := SaveState(l.opts.StatePath, l.state); err != nil {
			return sum, err
		}
		if l.opts.StatusPath != "" {
			if err := SaveStatus(l.opts.StatusPath, status); err != nil {
				return sum, err
			}
		}
	}
	sum.Served, sum.Unserved = 0, 0
	for _, site := range l.state.Sites {
		switch site.State {
		case SiteExit:
			sum.Served++
		case SiteUnserved:
			sum.Unserved++
		}
	}
	return sum, nil
}

func exitSuffix(site Site) string {
	if site.State == SiteExit {
		return " via " + site.Exit
	}
	return ""
}

func errSuffix(s string) string {
	if s == "" {
		return ""
	}
	return ", " + s
}

// decide routes one site's prefixes to the first exit that serves it.
func (l *Learner) decide(ctx context.Context, r resolved, handshakes map[string]int64, now time.Time) Site {
	site := Site{
		Domain:   r.domain,
		Prefixes: r.prefixes,
		Cloud:    r.cloud.Status,
		Verified: now.UTC(),
		Expires:  now.Add(l.opts.TTL).UTC(),
	}
	if r.cloud.Err != nil {
		site.CloudErr = r.cloud.Err.Error()
	}
	if r.cloud.Works() {
		l.release(r.prefixes)
		site.State = SiteCloud
		return site
	}

	owner := l.ownerOf(r.prefixes)
	if prev, ok := l.state.Sites[r.domain]; ok && prev.State == SiteUnserved &&
		now.Sub(prev.Verified) < l.opts.RetryUnserved && owner == "" && !l.exitsChanged {
		// Churning every exit for a name nothing can serve helps nobody. Keep
		// the verdict until the retry window passes; the cloud check above
		// still catches the site becoming reachable again, and an exit coming
		// back clears the backoff.
		prev.Cloud, prev.CloudErr = site.Cloud, site.CloudErr
		return prev
	}
	if owner != "" && l.healthy(owner, handshakes, now) {
		if l.probeAny(ctx, r.domain, r.ips, 0).Works() {
			site.State, site.Exit = SiteExit, owner
			return site
		}
	}

	for _, exit := range l.exits {
		if exit.ID == owner || !l.healthy(exit.ID, handshakes, now) {
			continue
		}
		if l.exitBlocks(exit.Network, r.domain) {
			l.opts.Logf("exit: skipping %s for %s: that network reports it blocked", exit.ID, r.domain)
			continue
		}
		if l.totalPrefixes()+len(r.prefixes) > l.opts.Limit {
			l.opts.Logf("exit: global cap of %d prefixes reached; not assigning %s", l.opts.Limit, r.domain)
			continue
		}
		if l.prefixCount(exit.ID)+len(r.prefixes) > exit.MaxPrefixes {
			l.opts.Logf("exit: %s is at its %d prefix cap; not assigning %s", exit.ID, exit.MaxPrefixes, r.domain)
			continue
		}
		l.assign(r.prefixes, exit.ID)
		if l.probeAny(ctx, r.domain, r.ips, 0).Works() {
			site.State, site.Exit = SiteExit, exit.ID
			return site
		}
	}

	l.release(r.prefixes)
	site.State = SiteUnserved
	return site
}

// resolveAndProbeCloud resolves a name and asks it over the cloud exit.
func (l *Learner) resolveAndProbeCloud(ctx context.Context, domain string) resolved {
	out := resolved{domain: domain}
	resolveCtx, cancel := context.WithTimeout(ctx, l.opts.Timeout)
	ips, err := net.DefaultResolver.LookupHost(resolveCtx, domain)
	cancel()
	if err != nil || len(ips) == 0 {
		return out
	}
	if len(ips) > 6 {
		ips = ips[:6]
	}
	out.prefixes = PrefixesFor(ips)
	if len(out.prefixes) == 0 {
		return out
	}
	if len(ips) > 3 {
		ips = ips[:3]
	}
	out.ips = ips
	out.cloud = l.probeAny(ctx, domain, ips, CloudMark)
	out.ok = true
	return out
}

// probeAny tries up to three addresses and returns the best answer: a reply
// beats a handshake, and a handshake beats a failure.
func (l *Learner) probeAny(ctx context.Context, domain string, ips []string, mark int) ProbeResult {
	var best ProbeResult
	for _, ip := range ips {
		res := l.probeFn(ctx, domain, ip, mark)
		if res.Status != 0 {
			return res
		}
		if res.Handshake {
			best = res
			continue
		}
		if best.Err == nil && best.Status == 0 && !best.Handshake {
			best = res
		}
	}
	return best
}

// probe dials one address, completes TLS, and asks for "/". A server that
// closes after the handshake still proves the path works, which is what an
// exit is being judged on.
func (l *Learner) probe(ctx context.Context, domain, ip string, mark int) ProbeResult {
	dialer := &net.Dialer{Timeout: l.opts.Timeout}
	if mark != 0 {
		dialer.Control = markControl(mark)
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	tc := tls.Client(conn, &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		// A certificate that names another host still proves the path got
		// somewhere; that address just is not a website for this name.
		return ProbeResult{Handshake: nameMismatch(err), Err: err}
	}
	req := "GET / HTTP/1.1\r\nHost: " + domain + "\r\nUser-Agent: " + probeUserAgent +
		"\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n"
	if _, err := tc.Write([]byte(req)); err != nil {
		return ProbeResult{Handshake: true, Err: err}
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	if err != nil {
		// Handshake done, then the server closed without a reply. The path
		// works; hosts that only serve files do this for "/".
		return ProbeResult{Handshake: true, Err: err}
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ProbeResult{Handshake: true, Err: fmt.Errorf("unexpected status line %q", strings.TrimSpace(line))}
	}
	status, convErr := strconv.Atoi(fields[1])
	if convErr != nil {
		return ProbeResult{Handshake: true, Err: fmt.Errorf("unexpected status %q", fields[1])}
	}
	return ProbeResult{Handshake: true, Status: status}
}

// ownerOf returns the exit a prefix set is currently assigned to. Conflicting
// assignments, which can only happen through a shared /24, are released: an
// address has one exit, and the next decision prefers a single one.
func (l *Learner) ownerOf(prefixes []string) string {
	owner := ""
	for _, prefix := range prefixes {
		id, ok := l.state.Assignments[prefix]
		if !ok || id == "" {
			continue
		}
		if owner == "" {
			owner = id
			continue
		}
		if owner != id {
			l.opts.Logf("exit: %s resolves into prefixes owned by both %s and %s; releasing", strings.Join(prefixes, " "), owner, id)
			l.release(prefixes)
			return ""
		}
	}
	return owner
}

// assign moves a prefix set to one exit and updates the data path.
func (l *Learner) assign(prefixes []string, id string) {
	touched := map[string]bool{}
	for _, prefix := range prefixes {
		if old, ok := l.state.Assignments[prefix]; ok && old != "" {
			touched[old] = true
		}
		l.state.Assignments[prefix] = id
	}
	touched[id] = true
	for exitID := range touched {
		l.applyAllowed(exitID)
	}
	for _, prefix := range prefixes {
		l.addRoute(prefix)
	}
}

// release returns a prefix set to the cloud exit.
func (l *Learner) release(prefixes []string) {
	touched := map[string]bool{}
	for _, prefix := range prefixes {
		if old, ok := l.state.Assignments[prefix]; ok && old != "" {
			touched[old] = true
		}
		delete(l.state.Assignments, prefix)
		l.removeRoute(prefix)
	}
	for exitID := range touched {
		l.applyAllowed(exitID)
	}
}

// totalPrefixes is the global assignment count.
func (l *Learner) totalPrefixes() int { return len(l.state.Assignments) }

// exitBlocks reports whether the exit's own network is known to block a
// domain. The active probe decides in the end; this only skips hopeless
// candidates without spending a request.
func (l *Learner) exitBlocks(network, domain string) bool {
	if network == "" {
		return false
	}
	if l.blocked == nil {
		l.blocked = map[string]map[string]bool{}
	}
	blocked, ok := l.blocked[network]
	if !ok {
		blocked = map[string]bool{}
		if data, err := os.ReadFile(filepath.Join(l.opts.FeedDir, network+".json")); err == nil {
			var feed struct {
				Domains map[string]struct {
					State string `json:"state"`
				} `json:"domains"`
			}
			if json.Unmarshal(data, &feed) == nil {
				for name, obs := range feed.Domains {
					if obs.State == "blocked" {
						blocked[strings.ToLower(name)] = true
					}
				}
			}
		}
		l.blocked[network] = blocked
	}
	return blocked[domain]
}

// prefixCount is how many prefixes an exit currently carries.
func (l *Learner) prefixCount(id string) int {
	n := 0
	for _, owner := range l.state.Assignments {
		if owner == id {
			n++
		}
	}
	return n
}

// applyAllowed pushes the per-exit allowed-ips list to WireGuard. The list is
// what maps a destination prefix to an exit on a shared interface.
func (l *Learner) applyAllowed(id string) {
	exit, ok := l.exitByID(id)
	if !ok {
		l.opts.Logf("exit: %s is not in the registry; remove it with deploy/remove-exit.sh", id)
		return
	}
	var prefixes []string
	seen := map[string]bool{}
	for prefix, owner := range l.state.Assignments {
		if owner == id && !seen[prefix] {
			prefixes = append(prefixes, prefix)
			seen[prefix] = true
		}
	}
	if exit.Address != "" {
		addr := exit.Address
		if ip := net.ParseIP(addr); ip != nil {
			addr = ip.String() + "/32"
		} else if !strings.Contains(addr, "/") {
			addr += "/32"
		}
		if !seen[addr] {
			prefixes = append(prefixes, addr)
			seen[addr] = true
		}
	}
	sort.Strings(prefixes)
	list := strings.Join(prefixes, ",")
	if prev, seen := l.lists[id]; seen && prev == list {
		return
	}
	if prev, seen := l.lists[id]; !seen || len(strings.Split(prev, ",")) != len(prefixes) || (prev == "" && len(prefixes) > 0) {
		l.opts.Logf("exit: %s carries %d allowed entries", id, len(prefixes))
	}
	if l.opts.DryRun {
		l.lists[id] = list
		return
	}
	if err := l.setAllowed(l.opts.Dev, exit.PubKey, list); err != nil {
		l.opts.Logf("exit: could not set allowed-ips for %s: %v", id, err)
		return
	}
	l.lists[id] = list
}

func (l *Learner) exitByID(id string) (Exit, bool) {
	for _, exit := range l.reg.Exits {
		if exit.ID == id {
			return exit, true
		}
	}
	return Exit{}, false
}

// noteExitHealth records health transitions so a returning exit is used at
// once. The first cycle after a start counts every healthy exit as returning,
// which is what an operator restarting the unit expects.
func (l *Learner) noteExitHealth(handshakes map[string]int64, now time.Time) {
	if l.wasHealthy == nil {
		l.wasHealthy = map[string]bool{}
	}
	l.exitsChanged = false
	for _, exit := range l.exits {
		healthy := l.healthy(exit.ID, handshakes, now)
		if healthy && !l.wasHealthy[exit.ID] {
			l.exitsChanged = true
		}
		l.wasHealthy[exit.ID] = healthy
	}
}

// healthy reports whether an exit has handshaked recently.
func (l *Learner) healthy(id string, handshakes map[string]int64, now time.Time) bool {
	exit, ok := l.exitByID(id)
	if !ok || !exit.Enabled {
		return false
	}
	at, ok := handshakes[exit.PubKey]
	if !ok || at == 0 {
		return false
	}
	return now.Unix()-at <= int64(l.opts.HealthWindow.Seconds())
}

func (l *Learner) handshakes() map[string]int64 {
	out := map[string]int64{}
	if l.opts.DryRun {
		// A dry run cannot ask the kernel what is live, so treat every enabled
		// exit as healthy and let the probes decide.
		now := time.Now().Unix()
		for _, exit := range l.reg.Exits {
			if exit.Enabled {
				out[exit.PubKey] = now
			}
		}
		return out
	}
	raw, err := exec.Command("wg", "show", l.opts.Dev, "latest-handshakes").Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		var at int64
		if _, err := fmt.Sscan(fields[1], &at); err == nil {
			out[fields[0]] = at
		}
	}
	return out
}

// prune drops sites no longer reported blocked and releases their prefixes.
func (l *Learner) prune(seen map[string]bool, now time.Time) {
	for domain, site := range l.state.Sites {
		if seen[domain] {
			continue
		}
		if now.After(site.Expires) {
			delete(l.state.Sites, domain)
			l.release(site.Prefixes)
		}
	}
	// An assignment with no site behind it is stale.
	live := map[string]bool{}
	for _, site := range l.state.Sites {
		for _, prefix := range site.Prefixes {
			live[prefix] = true
		}
	}
	for prefix := range l.state.Assignments {
		if !live[prefix] {
			delete(l.state.Assignments, prefix)
			l.removeRoute(prefix)
		}
	}
}

// addRoute/removeRoute keep the main table in step. Routes carry no next hop:
// WireGuard picks the exit from the prefix's allowed-ips owner.
func (l *Learner) addRoute(prefix string) {
	if l.applied[prefix] {
		return
	}
	if l.opts.DryRun {
		l.applied[prefix] = true
		return
	}
	if err := l.addRouteFn(prefix); err != nil {
		l.opts.Logf("exit: could not route %s: %v", prefix, err)
		return
	}
	l.applied[prefix] = true
}

func (l *Learner) removeRoute(prefix string) {
	if !l.applied[prefix] {
		return
	}
	delete(l.applied, prefix)
	if l.opts.DryRun {
		return
	}
	if err := l.delRouteFn(prefix); err != nil {
		// Already gone is fine.
		return
	}
}

// syncRoutes makes the kernel match the assignments, which also heals a wg0
// restart that dropped interface routes.
func (l *Learner) syncRoutes() {
	if l.opts.DryRun {
		return
	}
	kernel := l.kernelRoutes()
	want := map[string]bool{}
	for prefix := range l.state.Assignments {
		want[prefix] = true
	}
	for prefix := range want {
		if !kernel[prefix] {
			l.applied[prefix] = false
			l.addRoute(prefix)
		}
	}
	for prefix := range kernel {
		if !want[prefix] {
			l.applied[prefix] = true
			l.removeRoute(prefix)
		}
	}
}

func (l *Learner) kernelRoutes() map[string]bool {
	out := map[string]bool{}
	raw, err := exec.Command("ip", "route", "show", "dev", l.opts.Dev).Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.Contains(fields[0], "/") {
			continue
		}
		if fields[0] == "10.88.0.0/24" {
			continue
		}
		out[fields[0]] = true
	}
	return out
}

func (l *Learner) candidates() ([]Candidate, error) {
	fromFeed, err := Candidates(l.opts.FeedDir)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(fromFeed))
	out := make([]Candidate, 0, len(fromFeed))
	for _, c := range fromFeed {
		seen[c.Domain] = true
		out = append(out, c)
	}
	extra, err := ExtraDomains(l.opts.ExtraDomains)
	if err != nil {
		return nil, err
	}
	for _, c := range extra {
		if !seen[c.Domain] {
			seen[c.Domain] = true
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

// ensureCloudRouting pins the cloud probe to its own table. The cloud check
// must not follow a learned route, or it would verify the exit being tested.
func (l *Learner) ensureCloudRouting() error {
	gateway, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("read the default route: %w", err)
	}
	if gateway == "" {
		return fmt.Errorf("no default route")
	}
	if l.opts.DryRun {
		return nil
	}
	if err := run("ip", "route", "replace", "default", "via", gateway, "dev", l.opts.CloudDev, "table", fmt.Sprint(cloudTable)); err != nil {
		return err
	}
	_ = run("ip", "rule", "add", "fwmark", fmt.Sprintf("0x%x/0xff", CloudMark), "lookup", fmt.Sprint(cloudTable), "priority", "90")
	return nil
}

func (l *Learner) buildStatus(now time.Time, handshakes map[string]int64) Status {
	status := Status{
		Sites:       l.state.Sites,
		Assignments: l.state.Assignments,
		Unserved:    []string{},
	}
	healthyAny := false
	for _, exit := range l.reg.Exits {
		es := ExitStatus{
			ID:        exit.ID,
			Label:     exit.Label,
			Enabled:   exit.Enabled,
			Handshake: handshakes[exit.PubKey],
			Prefixes:  l.prefixCount(exit.ID),
		}
		for _, site := range l.state.Sites {
			if site.Exit == exit.ID {
				es.Sites++
			}
		}
		es.Healthy = exit.Enabled && l.healthy(exit.ID, handshakes, now)
		if es.Healthy {
			healthyAny = true
		}
		if exit.Enabled && !es.Healthy {
			es.Error = "no recent handshake"
		}
		status.Exits = append(status.Exits, es)
	}
	for _, site := range l.state.Sites {
		if site.State == SiteUnserved {
			status.Unserved = append(status.Unserved, site.Domain)
		}
	}
	sort.Strings(status.Unserved)
	status.AllDown = len(l.reg.Exits) > 0 && !healthyAny
	return status
}

func defaultGateway() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "via" {
			return fields[i+1], nil
		}
	}
	return "", nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
