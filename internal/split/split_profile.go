package split

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"egress/internal/core"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	splitSeedURL     = "https://bypass.breadway.dev/api/seed"
	splitReportURL   = "https://bypass.breadway.dev/api/blocked-report"
	splitReportEvery = 5 * time.Minute
	splitReportBatch = 20
	splitQueueMax    = 400
	splitHTTPTimeout = 10 * time.Second
)

// EvidenceFeed marks a domain learned from another device rather than probed
// here.
const EvidenceFeed Evidence = "feed"

type feedDomain struct {
	Domain    string `json:"domain"`
	Evidence  string `json:"evidence"`
	Count     int    `json:"count"`
	Contested bool   `json:"contested,omitempty"`
	// Recheck asks the device that believes the domain is allowed to probe
	// again; Verify asks the device that believes it is blocked to confirm.
	Recheck bool `json:"recheck,omitempty"`
	Verify  bool `json:"verify,omitempty"`
}

type feedProtocol struct {
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Count    int    `json:"count"`
}

type feedResponse struct {
	Version   int            `json:"version"`
	NetworkID string         `json:"network_id"`
	Domains   []feedDomain   `json:"domains"`
	Protocols []feedProtocol `json:"protocols,omitempty"`
}

type splitDomainReport struct {
	Domain   string `json:"domain"`
	State    string `json:"state,omitempty"`
	Evidence string `json:"evidence"`
	Final    bool   `json:"final,omitempty"`
}

type splitProtocolReport struct {
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Evidence string `json:"evidence"`
}

type splitReport struct {
	Device    string                `json:"device"`
	NetworkID string                `json:"network_id"`
	Domains   []splitDomainReport   `json:"domains"`
	Protocols []splitProtocolReport `json:"protocols,omitempty"`
}

// splitReporter batches newly blocked domains and shares the merged feed.
// Reporting is limited to domains this device classified as blocked; no
// requests, timestamps or browsing history leave the machine.
type splitReporter struct {
	mu       sync.Mutex
	device   string
	network  string
	dir      string
	queue    map[string]Evidence
	client   *http.Client
	log      *log.Logger
	disabled bool

	// protocols is what this device last observed about outbound protocols;
	// protocolsDirty is set when they have not been shared yet.
	protocols      []splitProtocolReport
	protocolsDirty bool
	// recheck probes a contested domain and returns the answer to share.
	recheck func(context.Context, string) (string, string)

	// test hooks
	seedURL   string
	reportURL string
	mergeFunc func([]feedDomain, []feedProtocol)
}

func newSplitReporter(network, dir string, logger *log.Logger) *splitReporter {
	if dir == "" {
		dir = ProfileDir()
	}
	r := &splitReporter{
		device:    deviceIDAt(dir),
		dir:       dir,
		network:   network,
		queue:     map[string]Evidence{},
		client:    &http.Client{Timeout: splitHTTPTimeout},
		log:       logger,
		seedURL:   splitSeedURL,
		reportURL: splitReportURL,
	}
	if _, err := os.Stat(filepath.Join(dir, "split-no-report")); err == nil {
		r.disabled = true
		r.log.Printf("split: reporting disabled by split-no-report")
	}
	return r
}

func (r *splitReporter) SetNetwork(network string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if network == r.network {
		return
	}
	r.network = network
}

func (r *splitReporter) Report(domain string, evidence Evidence) {
	if r.disabled {
		return
	}
	domain = core.NormalizeDomain(domain)
	if domain == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) >= splitQueueMax {
		return
	}
	r.queue[domain] = evidence
}

func (r *splitReporter) pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.queue)
}

// Run flushes the queue on a timer and refreshes the feed at startup.
func (r *splitReporter) Run(ctx context.Context) {
	if r.disabled {
		return
	}
	go r.fetchFeed(ctx)
	tick := time.NewTicker(splitReportEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_ = r.flush(ctx)
		}
	}
}

func (r *splitReporter) flush(ctx context.Context) error {
	r.mu.Lock()
	if len(r.queue) == 0 && !r.protocolsDirty {
		r.mu.Unlock()
		return nil
	}
	network := r.network
	device := r.device
	batch := make([]splitDomainReport, 0, len(r.queue))
	for domain, evidence := range r.queue {
		batch = append(batch, splitDomainReport{Domain: domain, State: "blocked", Evidence: string(evidence)})
		if len(batch) >= splitReportBatch {
			break
		}
	}
	protocols := r.protocols
	if !r.protocolsDirty {
		protocols = nil
	}
	r.mu.Unlock()

	payload, err := json.Marshal(splitReport{
		Device:    device,
		NetworkID: NetworkID(network),
		Domains:   batch,
		Protocols: protocols,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.reportURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		log.Printf("split: report failed, keeping %d queued: %v", len(batch), err)
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("split: report rejected: %s", resp.Status)
		return errors.New(resp.Status)
	}
	r.mu.Lock()
	for _, d := range batch {
		delete(r.queue, d.Domain)
	}
	r.protocolsDirty = false
	r.mu.Unlock()
	log.Printf("split: reported %d domains for %s", len(batch), network)
	return nil
}

func (r *splitReporter) fetchFeed(ctx context.Context) {
	if r.disabled {
		return
	}
	r.mu.Lock()
	network := r.network
	r.mu.Unlock()

	u := r.seedURL + "?n=" + NetworkID(network)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	resp, err := r.client.Do(req)
	if err != nil {
		log.Printf("split: feed fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("split: feed status %s", resp.Status)
		return
	}
	var feed feedResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&feed); err != nil {
		log.Printf("split: feed decode: %v", err)
		return
	}
	log.Printf("split: feed has %d domains and %d protocol notes", len(feed.Domains), len(feed.Protocols))
	r.merge(feed.Domains, feed.Protocols)
}

// merge writes feed entries into the profile as blocked. It is called from the
// reporter goroutine, so the caller does it through the controller to keep the
// profile lock honest.
func (r *splitReporter) merge(domains []feedDomain, protocols []feedProtocol) {
	r.mu.Lock()
	cb := r.mergeFunc
	r.mu.Unlock()
	if cb != nil {
		cb(domains, protocols)
	}
}

// mergeFunc is installed by the split controller.
func (r *splitReporter) SetMergeFunc(fn func([]feedDomain, []feedProtocol)) {
	r.mu.Lock()
	r.mergeFunc = fn
	r.mu.Unlock()
}

// ReportFinal shares the answer to a re-check or verification the server asked
// for while resolving a conflict. It is sent immediately: the whole point is
// to settle the domain without waiting for the batch timer.
func (r *splitReporter) ReportFinal(ctx context.Context, domain, state, evidence string) {
	if r.disabled {
		return
	}
	r.mu.Lock()
	network := r.network
	device := r.device
	r.mu.Unlock()
	payload, err := json.Marshal(splitReport{
		Device:    device,
		NetworkID: NetworkID(network),
		Domains:   []splitDomainReport{{Domain: domain, State: state, Evidence: evidence, Final: true}},
	})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.reportURL, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		log.Printf("split: final observation failed: %v", err)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	log.Printf("split: conflict answer %s=%s (%s)", domain, state, evidence)
}

// SetProtocols records this device's protocol observations for the next report.
func (r *splitReporter) SetProtocols(protocols []splitProtocolReport) {
	r.mu.Lock()
	r.protocols = protocols
	r.protocolsDirty = true
	r.mu.Unlock()
}

// mergeProtocols records the shared protocol picture. Only states this device
// has no measurement for are filled, so a local observation wins.
func mergeProtocols(p *Profile, protocols []feedProtocol) int {
	if p.Protocols == nil {
		p.Protocols = map[string]string{}
	}
	changed := 0
	for _, proto := range protocols {
		if proto.State == "" || p.Protocols[proto.Protocol] != "" {
			continue
		}
		p.Protocols[proto.Protocol] = proto.State
		changed++
	}
	return changed
}

// ProtocolStates returns the shared protocol picture, for reports and diagnose.
func (p *Profile) ProtocolStates() map[string]string {
	out := map[string]string{}
	for k, v := range p.Protocols {
		out[k] = v
	}
	return out
}

// mergeFeedDomains adds feed entries as blocked. It returns how many were new.
func mergeFeedDomains(p *Profile, domains []feedDomain, now time.Time) int {
	added := 0
	for _, d := range domains {
		domain := core.NormalizeDomain(d.Domain)
		if !plausibleDomain(domain) || probeIgnoredName(domain) {
			continue
		}
		if p.State(domain, now) == StateBlocked {
			continue
		}
		p.AddBlocked(domain, EvidenceFeed, now)
		added++
	}
	return added
}

func plausibleDomain(domain string) bool {
	if len(domain) < 3 || len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	for _, r := range domain {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}

func deviceIDAt(dir string) string {
	path := filepath.Join(dir, "device-id")
	if data, err := os.ReadFile(path); err == nil {
		id := strings.TrimSpace(string(data))
		if len(id) >= 16 && len(id) <= 64 {
			return id
		}
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "unknown"
	}
	id := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(dir, 0700); err != nil {
		return id
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0600); err != nil {
		return id
	}
	return id
}

// DomainState is the split-mode classification for one domain on one network.
type DomainState string

const (
	StateUnknown DomainState = "unknown"
	StateAllowed DomainState = "allowed"
	StateBlocked DomainState = "blocked"
)

// Evidence records why a domain was classified. It is stored in the profile so
// a later audit can tell a TLS stall from a certificate substitution.
type Evidence string

const (
	EvidenceNone             Evidence = ""
	EvidenceConnectStall     Evidence = "connect-stall"
	EvidenceTLSStall         Evidence = "tls-stall"
	EvidenceCertSubstitution Evidence = "cert-substitution"
	EvidenceIPRejected       Evidence = "ip-rejected"
	EvidenceSeed             Evidence = "seed"
)

const (
	// A domain must fail this many probes in a row before it is treated as
	// blocked, so one flaky moment does not tunnel half the internet.
	blockedAfterFailures = 2
	// An allowed verdict expires; the domain is re-probed after this long.
	allowedTTL = 24 * time.Hour
	// Bounds on the stored profile.
	maxProfileEntries = 2000
)

// DomainEntry is one row in a network profile.
type DomainEntry struct {
	State     DomainState `json:"state"`
	Evidence  Evidence    `json:"evidence,omitempty"`
	Failures  int         `json:"failures,omitempty"`
	LearnedAt time.Time   `json:"learned_at,omitempty"`
	LastProbe time.Time   `json:"last_probe,omitempty"`
	LastOK    time.Time   `json:"last_ok,omitempty"`
}

// Profile is the learned block list for one network. It is deliberately small
// and text: domains and evidence, never browsing history.
type Profile struct {
	Version int                    `json:"version"`
	Network string                 `json:"network"`
	Updated time.Time              `json:"updated"`
	Entries map[string]DomainEntry `json:"entries"`
	// Protocols is what the network was last seen to allow outbound: udp,
	// tcp, icmp, dns. Shared between devices so a joining client can start
	// in the right mode instead of rediscovering a UDP block.
	Protocols map[string]string `json:"protocols,omitempty"`
}

func NewProfile(network string) *Profile {
	return &Profile{Version: 1, Network: network, Entries: map[string]DomainEntry{},
		Protocols: map[string]string{}}
}

// NetworkID is the key the shared table uses. It hashes the SSID so the server
// never stores the name. The pepper makes the hash domain-specific, not secret:
// an SSID has a small search space.
func NetworkID(network string) string {
	sum := sha256.Sum256([]byte("egress-split-v1:" + strings.ToLower(strings.TrimSpace(network))))
	return hex.EncodeToString(sum[:])[:32]
}

// NetworkKey identifies a network by SSID and gateway. Roaming between APs on
// the same gateway keeps one profile; a new gateway starts a new one.
func NetworkKey(ssid, gateway string) string {
	ssid = strings.TrimSpace(ssid)
	gateway = strings.TrimSpace(gateway)
	if ssid == "" {
		ssid = "unknown"
	}
	if gateway == "" {
		gateway = "unknown"
	}
	return ssid + "|" + gateway
}

// State returns the current state, expiring stale allowed verdicts.
func (p *Profile) State(domain string, now time.Time) DomainState {
	entry, ok := p.Entries[core.NormalizeDomain(domain)]
	if !ok {
		return StateUnknown
	}
	if entry.State == StateAllowed && !entry.LastOK.IsZero() && now.Sub(entry.LastOK) > allowedTTL {
		return StateUnknown
	}
	return entry.State
}

// RecordProbe applies a definitive probe result. Transient failures must not be
// recorded: the caller only calls this when the classifier is sure.
func (p *Profile) RecordProbe(domain string, evidence Evidence, blocked bool, now time.Time) {
	domain = core.NormalizeDomain(domain)
	if domain == "" {
		return
	}
	if p.Entries == nil {
		p.Entries = map[string]DomainEntry{}
	}
	if p.Protocols == nil {
		p.Protocols = map[string]string{}
	}
	entry, ok := p.Entries[domain]
	if !ok && len(p.Entries) >= maxProfileEntries {
		return
	}
	entry.LastProbe = now
	if !blocked {
		entry.State = StateAllowed
		entry.Evidence = EvidenceNone
		entry.Failures = 0
		entry.LastOK = now
		p.Entries[domain] = entry
		p.Updated = now
		return
	}
	entry.Failures++
	if entry.Failures >= blockedAfterFailures {
		if entry.State != StateBlocked {
			entry.LearnedAt = now
		}
		entry.State = StateBlocked
		entry.Evidence = evidence
	}
	p.Entries[domain] = entry
	p.Updated = now
}

// AddBlocked records a domain as blocked without probing, for seed and feed
// entries. It still counts as a full failure streak so a single later success
// can clear it.
func (p *Profile) AddBlocked(domain string, evidence Evidence, now time.Time) {
	domain = core.NormalizeDomain(domain)
	if domain == "" || len(p.Entries) >= maxProfileEntries {
		return
	}
	entry := p.Entries[domain]
	entry.State = StateBlocked
	entry.Evidence = evidence
	entry.Failures = blockedAfterFailures
	if entry.LearnedAt.IsZero() {
		entry.LearnedAt = now
	}
	p.Entries[domain] = entry
	p.Updated = now
}

// BlockedDomains returns the domains currently routed into the tunnel.
func (p *Profile) BlockedDomains(now time.Time) []string {
	var out []string
	for domain, entry := range p.Entries {
		if entry.State == StateBlocked {
			out = append(out, domain)
		}
	}
	return out
}

// ProfileDir is where split profiles live. Linux uses the system state
// directory; Windows uses the install directory; elsewhere the user config
// directory.
func ProfileDir() string {
	switch runtime.GOOS {
	case "linux":
		return "/var/lib/egress"
	case "windows":
		return `C:\ProgramData\egress`
	default:
		if dir, err := os.UserConfigDir(); err == nil {
			return filepath.Join(dir, "egress")
		}
		return "."
	}
}

// ProfilePath is the file for one network key in the system state directory.
func ProfilePath(network string) string {
	return ProfilePathIn(ProfileDir(), network)
}

// ProfilePathIn is the file for one network key in a caller-provided directory.
// The per-user proxy keeps its own profile so it can write without the SYSTEM
// directory's permissions.
func ProfilePathIn(dir, network string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, network)
	if safe == "" {
		safe = "unknown"
	}
	return filepath.Join(dir, "split-"+safe+".json")
}

// ProxyDir is the per-user state directory for the split proxy and tray.
func ProxyDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "egress")
	}
	return "."
}

// LoadProfile reads the profile for a network. A missing file is a fresh one.
func LoadProfile(path, network string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewProfile(network), nil
	}
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if p.Entries == nil {
		p.Entries = map[string]DomainEntry{}
	}
	if p.Protocols == nil {
		p.Protocols = map[string]string{}
	}
	if p.Network == "" {
		p.Network = network
	}
	return &p, nil
}

// Save writes the profile atomically so a crash cannot truncate the list.
func (p *Profile) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
