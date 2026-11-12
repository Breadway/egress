package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// dnsQueryName returns the first question name from a DNS query, lowercased.
// Empty on malformed input, which the resolver then ignores.
func dnsQueryName(query []byte) string {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) == 0 {
		return ""
	}
	name, _, ok := dnsNameAt(query, 12)
	if !ok {
		return ""
	}
	return NormalizeDomain(name)
}

// dnsNameAt decodes a possibly compressed name starting at off and returns the
// name plus the offset just past the name in the original position.
func dnsNameAt(msg []byte, off int) (string, int, bool) {
	var name []byte
	next := off
	jumped := false
	for steps := 0; steps < 64; steps++ {
		if off >= len(msg) {
			return "", 0, false
		}
		length := int(msg[off])
		switch {
		case length == 0:
			off++
			if !jumped {
				next = off
			}
			return string(name), next, true
		case length&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if !jumped {
				next = off + 2
				jumped = true
			}
			if ptr >= len(msg) {
				return "", 0, false
			}
			off = ptr
		case length&0xc0 != 0:
			return "", 0, false
		default:
			if off+1+length > len(msg) {
				return "", 0, false
			}
			if len(name) > 0 {
				name = append(name, '.')
			}
			name = append(name, msg[off+1:off+1+length]...)
			off += 1 + length
		}
	}
	return "", 0, false
}

// dnsAnswerIPv4 extracts A records from a response and the smallest TTL among
// them. A response with no A records returns nil and a zero TTL.
func dnsAnswerIPv4(resp []byte) ([]net.IP, time.Duration) {
	if len(resp) < 12 {
		return nil, 0
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, ok := dnsNameAt(resp, off)
		if !ok || next+4 > len(resp) {
			return nil, 0
		}
		off = next + 4
	}

	var ips []net.IP
	var minTTL uint32
	for i := 0; i < an; i++ {
		_, next, ok := dnsNameAt(resp, off)
		if !ok || next+10 > len(resp) {
			break
		}
		rrType := binary.BigEndian.Uint16(resp[next : next+2])
		ttl := binary.BigEndian.Uint32(resp[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(resp[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdlen > len(resp) {
			break
		}
		if rrType == 1 && rdlen == 4 {
			ip := make(net.IP, 4)
			copy(ip, resp[rdata:rdata+4])
			ips = append(ips, ip)
			if minTTL == 0 || ttl < minTTL {
				minTTL = ttl
			}
		}
		off = rdata + rdlen
	}
	if len(ips) == 0 {
		return nil, 0
	}
	return ips, time.Duration(minTTL) * time.Second
}

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
	Domain   string `json:"domain"`
	Evidence string `json:"evidence"`
	Count    int    `json:"count"`
}

type feedResponse struct {
	Version int          `json:"version"`
	Network string       `json:"network"`
	Domains []feedDomain `json:"domains"`
}

type splitDomainReport struct {
	Domain   string `json:"domain"`
	Evidence string `json:"evidence"`
}

type splitReport struct {
	Device  string              `json:"device"`
	Network string              `json:"network"`
	Domains []splitDomainReport `json:"domains"`
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

	// test hooks
	seedURL   string
	reportURL string
	mergeFunc func([]feedDomain)
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
	domain = NormalizeDomain(domain)
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
	if len(r.queue) == 0 {
		r.mu.Unlock()
		return nil
	}
	network := r.network
	device := r.device
	batch := make([]splitDomainReport, 0, len(r.queue))
	for domain, evidence := range r.queue {
		batch = append(batch, splitDomainReport{Domain: domain, Evidence: string(evidence)})
		if len(batch) >= splitReportBatch {
			break
		}
	}
	r.mu.Unlock()

	payload, err := json.Marshal(splitReport{Device: device, Network: network, Domains: batch})
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
		debugf("split: report failed, keeping %d queued: %v", len(batch), err)
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		debugf("split: report rejected: %s", resp.Status)
		return errors.New(resp.Status)
	}
	r.mu.Lock()
	for _, d := range batch {
		delete(r.queue, d.Domain)
	}
	r.mu.Unlock()
	debugf("split: reported %d domains for %s", len(batch), network)
	return nil
}

func (r *splitReporter) fetchFeed(ctx context.Context) {
	if r.disabled {
		return
	}
	r.mu.Lock()
	network := r.network
	r.mu.Unlock()

	u := r.seedURL + "?network=" + url.QueryEscape(network)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	resp, err := r.client.Do(req)
	if err != nil {
		debugf("split: feed fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		debugf("split: feed status %s", resp.Status)
		return
	}
	var feed feedResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&feed); err != nil {
		debugf("split: feed decode: %v", err)
		return
	}
	debugf("split: feed has %d domains for %s", len(feed.Domains), network)
	r.merge(feed.Domains)
}

// merge writes feed entries into the profile as blocked. It is called from the
// reporter goroutine, so the caller does it through the controller to keep the
// profile lock honest.
func (r *splitReporter) merge(domains []feedDomain) {
	r.mu.Lock()
	cb := r.mergeFunc
	r.mu.Unlock()
	if cb != nil {
		cb(domains)
	}
}

// mergeFunc is installed by the split controller.
func (r *splitReporter) SetMergeFunc(fn func([]feedDomain)) {
	r.mu.Lock()
	r.mergeFunc = fn
	r.mu.Unlock()
}

// mergeFeedDomains adds feed entries as blocked. It returns how many were new.
func mergeFeedDomains(p *Profile, domains []feedDomain, now time.Time) int {
	added := 0
	for _, d := range domains {
		domain := NormalizeDomain(d.Domain)
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
}

func NewProfile(network string) *Profile {
	return &Profile{Version: 1, Network: network, Entries: map[string]DomainEntry{}}
}

// NormalizeDomain lowercases a domain and strips a trailing dot.
func NormalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
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
	entry, ok := p.Entries[NormalizeDomain(domain)]
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
	domain = NormalizeDomain(domain)
	if domain == "" {
		return
	}
	if p.Entries == nil {
		p.Entries = map[string]DomainEntry{}
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
	domain = NormalizeDomain(domain)
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
