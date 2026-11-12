package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
		if !plausibleDomain(domain) {
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
