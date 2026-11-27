package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"egress/internal/core"
	"egress/internal/split"
)

// cmdScan probes a list of domains to seed a new network, records the findings
// in this network's profile, and shares the blocked set with other devices.
func cmdScan(args []string) error {
	fs := newFlagSet("scan")
	concurrency := fs.Int("concurrency", 8, "parallel probes")
	timeout := fs.Duration("timeout", split.ProbeTimeout, "per-probe timeout")
	iface := fs.String("interface", "", "bind probes to this interface (Linux only)")
	list := fs.String("list", "", "file of domains, one per line (default: the built-in list)")
	top := fs.Int("top", 0, "scan the top N domains of a public ranking instead of the built-in list")
	source := fs.String("source", "", "ranking URL for --top (default Majestic Million CSV)")
	limit := fs.Int("limit", 0, "probe only the first N domains")
	quiet := fs.Bool("quiet", false, "print only the summary")
	preview := fs.Bool("preview", false, "scan and print without recording or sharing")
	noReport := fs.Bool("no-report", false, "do not share the blocked set with the fleet")
	debug := fs.Bool("debug", false, "trace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))
	if *concurrency > 128 {
		fmt.Fprintf(os.Stderr, "warning: --concurrency %d is above the DoH endpoint's reliable capacity (128); expect lookups to be rejected and results to come back inconclusive\n", *concurrency)
	}
	if *iface != "" && runtime.GOOS != "linux" {
		return errors.New("--interface binds the probe to a physical link and is Linux-only; omit it on this platform")
	}

	if !*preview {
		// The profile is root-owned: recording findings needs the same
		// privilege the supervisor has. Check before any list fetch or scan
		// that can take minutes, instead of printing a warning after it.
		if err := profileWritable(split.ProfileDir()); err != nil {
			return fmt.Errorf("scan records findings in %s, which needs root: run `sudo egress scan`, or add --preview to scan without recording (%v)", split.ProfileDir(), err)
		}
	}

	domains := fs.Args()
	if len(domains) == 0 {
		if *top > 0 {
			fetched, err := fetchRanking(context.Background(), *source, *top)
			if err != nil {
				return fmt.Errorf("fetch the ranking: %w", err)
			}
			if len(fetched) == 0 {
				return errors.New("the ranking produced no domains")
			}
			if len(fetched) < *top {
				fmt.Fprintf(os.Stderr, "ranking yielded %d domains, asked for %d\n", len(fetched), *top)
			}
			domains = fetched
		} else if *list != "" {
			file, err := os.Open(*list)
			if err != nil {
				return err
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					domains = append(domains, line)
				}
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		} else {
			domains = split.DefaultScanDomains()
		}
	}
	if *limit > 0 && len(domains) > *limit {
		domains = domains[:*limit]
	}
	if len(domains) == 0 {
		return errors.New("no domains to scan")
	}

	plat := newPlatform()
	dev, gateway, err := plat.DefaultRoute()
	if err != nil {
		return fmt.Errorf("find the default route: %w", err)
	}
	network, _ := currentNetwork(dev, gateway)

	// Scanning while DNS is broken records allowed and inconclusive results
	// that say nothing about the network. Refuse instead.
	check, cancelCheck := context.WithTimeout(context.Background(), 6*time.Second)
	_, resolveErr := core.LookupHost(check, "example.com")
	cancelCheck()
	if resolveErr != nil {
		return fmt.Errorf("cannot resolve names right now (%v); fix DNS before scanning", resolveErr)
	}

	fmt.Printf("scanning %d domains on %s with %d workers\n", len(domains), network, *concurrency)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(domains))*(*timeout)/time.Duration(*concurrency)*2+time.Minute)
	defer cancel()

	blocked := 0
	var done int64
	var progressMu sync.Mutex
	progress := func(split.ScanResult) {
		n := atomic.AddInt64(&done, 1)
		if *quiet || len(domains) < 50 {
			return
		}
		if n%100 != 0 && n != int64(len(domains)) {
			return
		}
		progressMu.Lock()
		fmt.Fprintf(os.Stderr, "\rscanned %d/%d", n, len(domains))
		if n == int64(len(domains)) {
			fmt.Fprintln(os.Stderr)
		}
		progressMu.Unlock()
	}
	results := split.ScanDomains(ctx, domains, split.ScanOptions{
		Concurrency: *concurrency,
		Timeout:     *timeout,
		Interface:   *iface,
		Resolve:     core.LookupHost,
		OnResult:    func(r split.ScanResult) { progress(r) },
	})

	allowed, unknown := 0, 0
	for _, r := range results {
		if r.Domain == "" {
			continue
		}
		switch r.State {
		case split.StateBlocked:
			blocked++
			if !*quiet {
				fmt.Printf("  blocked  %-32s %s\n", r.Domain, r.Evidence)
			}
		case split.StateAllowed:
			allowed++
		default:
			unknown++
		}
	}

	recorded := 0
	if *preview {
		fmt.Println("\npreview: nothing recorded, nothing shared")
	} else {
		var err error
		recorded, err = split.RecordScan(network, results)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not record the scan: %v\n", err)
		}
		if !*noReport {
			split.ReportScan(ctx, network, results)
		}
	}

	fmt.Printf("\nscanned %d: %d blocked, %d allowed, %d inconclusive; recorded %d in the profile\n",
		len(domains), blocked, allowed, unknown, recorded)
	return nil
}

// profileWritable proves the scan can write the network profile, which is
// owned by the supervisor's account. It creates and removes a temporary file
// rather than trusting the directory mode, and works on every platform.
func profileWritable(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".scan-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

// defaultRanking is a plain CSV whose third column is the domain. Majestic
// publishes it daily and the body streams, so taking a thousand rows does not
// download a million.
const defaultRanking = "https://downloads.majestic.com/majestic_million.csv"

// fetchRanking reads up to n domains from a ranking. It accepts a CSV with a
// domain column or a plain one-per-line list, stops as soon as n are found,
// and resolves the host through the egress listener.
func fetchRanking(ctx context.Context, source string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	if source == "" {
		source = defaultRanking
	}
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 10 * time.Second, Resolver: core.LocalResolver()}).DialContext,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	seen := make(map[string]bool, n)
	out := make([]string, 0, n)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := line
		if fields := strings.Split(line, ","); len(fields) >= 3 {
			domain = fields[2]
		}
		domain = strings.ToLower(strings.TrimSpace(domain))
		if !rankingDomain(domain) || seen[domain] {
			continue
		}
		seen[domain] = true
		out = append(out, domain)
		if len(out) >= n {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// rankingDomain rejects header rows, addresses and junk.
func rankingDomain(d string) bool {
	if d == "" || len(d) > 253 || strings.ContainsAny(d, " \t/:") || strings.Contains(d, `"`) {
		return false
	}
	if !strings.Contains(d, ".") || net.ParseIP(d) != nil {
		return false
	}
	return !strings.HasPrefix(d, ".")
}
