package exitroute

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// CloudMark and HomeMark select the routing table a probe leaves through.
	// They sit above the main table so a learned route cannot make the cloud
	// check go through the home exit it is meant to verify.
	CloudMark = 0x44
	HomeMark  = 0x45

	cloudTable = 812
	homeTable  = 811

	probeUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

// Options configures the learner.
type Options struct {
	FeedDir      string
	ExtraDomains string
	StatePath    string
	Interval     time.Duration
	TTL          time.Duration
	ExitDev      string
	CloudDev     string
	Limit        int
	Concurrency  int
	Timeout      time.Duration
	DryRun       bool
	Logf         func(format string, args ...any)
}

// Summary is one cycle's outcome.
type Summary struct {
	Candidates int
	Checked    int
	Learned    int
	Released   int
	Added      []string
	Removed    []string
}

// Learner compares sites over both exits and keeps the learned routes in place.
type Learner struct {
	opts    Options
	state   State
	applied map[string]bool
	cloud   *http.Client
	home    *http.Client
}

// New returns a learner with the given options and its saved state.
func New(opts Options) (*Learner, error) {
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Minute
	}
	if opts.TTL <= 0 {
		opts.TTL = 7 * 24 * time.Hour
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 12 * time.Second
	}
	if opts.ExitDev == "" {
		opts.ExitDev = "wg0"
	}
	if opts.CloudDev == "" {
		opts.CloudDev = "ens3"
	}
	if opts.Limit <= 0 {
		opts.Limit = 400
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	state, err := LoadState(opts.StatePath)
	if err != nil {
		return nil, err
	}
	l := &Learner{opts: opts, state: state, applied: map[string]bool{}}
	l.cloud = probeClient(opts.Timeout, CloudMark)
	l.home = probeClient(opts.Timeout, HomeMark)
	return l, nil
}

func probeClient(timeout time.Duration, mark int) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, Control: markControl(mark)}
	return &http.Client{
		Timeout: 2 * timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			ForceAttemptHTTP2:     true,
		},
	}
}

// ApplySavedRoutes restores the routes for the state on startup, so a reboot
// does not leave a learned prefix on the cloud exit again.
func (l *Learner) ApplySavedRoutes(now time.Time) error {
	desired := Desired(l.state, now, l.opts.Limit)
	add, remove := Reconcile(desired, l.routedByKernel())
	for _, prefix := range remove {
		l.removeRoute(prefix)
	}
	for _, prefix := range add {
		if err := l.addRoute(prefix); err != nil {
			return err
		}
	}
	return nil
}

// RunOnce performs one learning cycle.
func (l *Learner) RunOnce(ctx context.Context) (Summary, error) {
	var sum Summary
	now := time.Now()

	if err := l.ensureTestRouting(); err != nil {
		return sum, err
	}

	candidates, err := l.candidates()
	if err != nil {
		return sum, err
	}
	sum.Candidates = len(candidates)
	if len(candidates) == 0 {
		return sum, l.reconcile(now, &sum)
	}

	checked := make(map[string]int, len(candidates))
	var mu sync.Mutex
	sem := make(chan struct{}, l.opts.Concurrency)
	var wg sync.WaitGroup

	for _, candidate := range candidates {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			obs, ok := l.observe(ctx, candidate.Domain)
			if !ok {
				return
			}
			mu.Lock()
			checked[candidate.Domain] = obs.Home
			mu.Unlock()

			if l.applyObservation(obs, now) {
				l.opts.Logf("exit: %s refused the cloud exit (%d, %s) and serves the home exit (%d); routing %s",
					obs.Domain, obs.Cloud, obs.CloudErr, obs.Home, strings.Join(obs.Prefixes, " "))
			}
		}()
	}
	wg.Wait()

	sum.Checked = len(checked)
	if err := l.reconcile(now, &sum); err != nil {
		return sum, err
	}
	return sum, nil
}

// Run loops until the context is cancelled.
func (l *Learner) Run(ctx context.Context) error {
	if err := l.ApplySavedRoutes(time.Now()); err != nil {
		l.opts.Logf("exit: could not restore learned routes: %v", err)
	}
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
			l.opts.Logf("exit: checked %d of %d blocked names, %d learned, %d released",
				sum.Checked, sum.Candidates, sum.Learned, sum.Released)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
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

// observe resolves a site and asks it over both exits.
func (l *Learner) observe(ctx context.Context, domain string) (Observation, bool) {
	obs := Observation{Domain: domain}
	resolveCtx, cancel := context.WithTimeout(ctx, l.opts.Timeout)
	ips, err := net.DefaultResolver.LookupHost(resolveCtx, domain)
	cancel()
	if err != nil || len(ips) == 0 {
		return obs, false
	}
	if len(ips) > 6 {
		ips = ips[:6]
	}
	obs.Prefixes = PrefixesFor(ips)
	if len(obs.Prefixes) == 0 {
		return obs, false
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		status, err := requestStatus(ctx, l.cloud, domain)
		obs.Cloud = status
		if err != nil {
			obs.CloudErr = err.Error()
		}
	}()
	go func() {
		defer wg.Done()
		status, err := requestStatus(ctx, l.home, domain)
		obs.Home = status
		if err != nil {
			obs.HomeErr = err.Error()
		}
	}()
	wg.Wait()
	return obs, true
}

func requestStatus(ctx context.Context, client *http.Client, domain string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", probeUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}

// applyObservation updates the state for one checked site and reports whether
// it learned a prefix it did not already hold.
func (l *Learner) applyObservation(obs Observation, now time.Time) bool {
	// A site that no longer refuses the cloud exit releases every prefix it
	// held, whether or not the new answer resolves differently.
	if !ExitBlocked(obs) {
		for prefix, entry := range l.state.Entries {
			if entry.Domain == obs.Domain {
				delete(l.state.Entries, prefix)
			}
		}
		return false
	}
	fresh := false
	for _, prefix := range obs.Prefixes {
		if _, ok := l.state.Entries[prefix]; !ok {
			fresh = true
		}
		l.state.Entries[prefix] = EntryFor(obs, now, l.opts.TTL)
	}
	return fresh
}

// reconcile prunes expired entries, applies the difference and records it.
func (l *Learner) reconcile(now time.Time, sum *Summary) error {
	Prune(l.state, now)
	desired := Desired(l.state, now, l.opts.Limit)
	add, remove := Reconcile(desired, l.routedByKernel())

	for _, prefix := range remove {
		if err := l.removeRoute(prefix); err != nil {
			l.opts.Logf("exit: could not remove %s: %v", prefix, err)
			continue
		}
		sum.Removed = append(sum.Removed, prefix)
	}
	for _, prefix := range add {
		if err := l.addRoute(prefix); err != nil {
			l.opts.Logf("exit: could not route %s: %v", prefix, err)
			continue
		}
		sum.Added = append(sum.Added, prefix)
	}
	// A released prefix means at least one site is served by the cloud exit
	// again; count domains, not prefixes, for the summary line.
	released := map[string]bool{}
	for _, prefix := range remove {
		if entry, ok := l.state.Entries[prefix]; ok {
			released[entry.Domain] = true
		}
	}
	sum.Learned = len(sum.Added)
	sum.Released = len(released)

	if l.opts.DryRun {
		return nil
	}
	return SaveState(l.opts.StatePath, l.state)
}

// routedByKernel reports which learned prefixes the kernel actually holds. A
// wg0 restart drops interface routes, so trusting the in-memory set would leave
// a prefix on the cloud exit until the next state change.
func (l *Learner) routedByKernel() []string {
	known := make(map[string]bool, len(l.state.Entries)+len(l.applied))
	for prefix := range l.state.Entries {
		known[prefix] = true
	}
	for prefix := range l.applied {
		known[prefix] = true
	}
	if l.opts.DryRun {
		out := make([]string, 0, len(l.applied))
		for prefix := range l.applied {
			out = append(out, prefix)
		}
		return out
	}
	out, err := exec.Command("ip", "route", "show", "dev", l.opts.ExitDev).Output()
	if err != nil {
		routed := make([]string, 0, len(l.applied))
		for prefix := range l.applied {
			routed = append(routed, prefix)
		}
		return routed
	}
	var routed []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !known[fields[0]] {
			continue
		}
		routed = append(routed, fields[0])
	}
	return routed
}

func (l *Learner) addRoute(prefix string) error {
	l.opts.Logf("exit: routing %s via %s", prefix, l.opts.ExitDev)
	if l.opts.DryRun {
		l.applied[prefix] = true
		return nil
	}
	if err := run("ip", "route", "replace", prefix, "dev", l.opts.ExitDev); err != nil {
		return err
	}
	l.applied[prefix] = true
	return nil
}

func (l *Learner) removeRoute(prefix string) error {
	l.opts.Logf("exit: releasing %s back to the cloud exit", prefix)
	if l.opts.DryRun {
		delete(l.applied, prefix)
		return nil
	}
	if err := run("ip", "route", "del", prefix); err != nil {
		// Already gone is not an error.
		delete(l.applied, prefix)
		return nil
	}
	delete(l.applied, prefix)
	return nil
}

// ensureTestRouting pins each probe class to its own table. The cloud probe
// must not follow a learned route, and the home probe must not follow the
// default route.
func (l *Learner) ensureTestRouting() error {
	gateway, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("read the default route: %w", err)
	}
	if gateway == "" {
		return fmt.Errorf("no default route")
	}
	// The test tables are set up in dry-run too: without them the home probe
	// follows the cloud route and every comparison looks identical.
	if err := run("ip", "route", "replace", "default", "via", gateway, "dev", l.opts.CloudDev, "table", fmt.Sprint(cloudTable)); err != nil {
		return err
	}
	if err := run("ip", "route", "replace", "default", "dev", l.opts.ExitDev, "table", fmt.Sprint(homeTable)); err != nil {
		return err
	}
	for _, rule := range [][2]string{
		{fmt.Sprintf("0x%x/0xff", CloudMark), fmt.Sprint(cloudTable)},
		{fmt.Sprintf("0x%x/0xff", HomeMark), fmt.Sprint(homeTable)},
	} {
		_ = run("ip", "rule", "add", "fwmark", rule[0], "lookup", rule[1], "priority", "90")
	}
	return nil
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
