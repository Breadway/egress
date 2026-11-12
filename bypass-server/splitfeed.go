package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Split-mode feed. Clients report domains they classify as blocked on a given
// network, and fetch the merged list when they join that network, so a fresh
// device does not have to rediscover everything by probing.
//
// Only blocked domains are stored. No browsing history, no client IPs, and the
// endpoint is rate limited per source address.

const (
	splitBodyMax    = 64 << 10
	splitRateMax    = 60
	splitRateWindow = time.Hour
	maxSplitDomains = 2000
	maxSplitReport  = 50
)

var (
	splitDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	splitEvidence = map[string]bool{
		"connect-stall":     true,
		"tls-stall":         true,
		"cert-substitution": true,
		"ip-rejected":       true,
		"seed":              true,
		"feed":              true,
	}
)

type splitDomainReport struct {
	Domain   string `json:"domain"`
	Evidence string `json:"evidence"`
}

type splitReport struct {
	Device  string              `json:"device"`
	Network string              `json:"network"`
	Domains []splitDomainReport `json:"domains"`
}

type feedEntry struct {
	Evidence string `json:"evidence"`
	Count    int    `json:"count"`
	LastSeen string `json:"last_seen"`
}

type networkFeed struct {
	Version int                  `json:"version"`
	Network string               `json:"network"`
	Updated string               `json:"updated"`
	Domains map[string]feedEntry `json:"domains"`
}

func (s *server) splitDir() string { return filepath.Join(s.state, "split") }

func splitSlug(network string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(network) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 80 {
		out = out[:80]
	}
	if out == "" {
		out = "unknown"
	}
	return out
}

func (s *server) loadFeed(network string) networkFeed {
	feed := networkFeed{Version: 1, Network: network, Domains: map[string]feedEntry{}}
	data, err := os.ReadFile(filepath.Join(s.splitDir(), splitSlug(network)+".json"))
	if err != nil {
		return feed
	}
	if err := json.Unmarshal(data, &feed); err != nil || feed.Domains == nil {
		return networkFeed{Version: 1, Network: network, Domains: map[string]feedEntry{}}
	}
	return feed
}

func (s *server) saveFeed(feed networkFeed) error {
	if err := os.MkdirAll(s.splitDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(feed, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.splitDir(), splitSlug(feed.Network)+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func validSplitNetwork(network string) bool {
	network = strings.TrimSpace(network)
	return len(network) >= 1 && len(network) <= 120
}

func validSplitDomain(domain string) bool {
	return len(domain) <= 253 && splitDomainRe.MatchString(domain)
}

func (s *server) apiBlockedReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allow(s.splits, clientIP(r), splitRateMax, splitRateWindow) {
		http.Error(w, "too many reports; try again later", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, splitBodyMax)
	var rep splitReport
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	rep.Device = truncateText(strings.TrimSpace(rep.Device), 64)
	rep.Network = truncateText(strings.TrimSpace(rep.Network), 120)
	if rep.Device == "" || !validSplitNetwork(rep.Network) {
		http.Error(w, "bad device or network", http.StatusBadRequest)
		return
	}
	if len(rep.Domains) == 0 || len(rep.Domains) > maxSplitReport {
		http.Error(w, "bad domain count", http.StatusBadRequest)
		return
	}

	s.feedMu.Lock()
	defer s.feedMu.Unlock()
	feed := s.loadFeed(rep.Network)
	now := time.Now().UTC().Format(time.RFC3339)
	added := 0
	for _, d := range rep.Domains {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.Domain)), ".")
		if !validSplitDomain(domain) || !splitEvidence[d.Evidence] {
			continue
		}
		entry, ok := feed.Domains[domain]
		if !ok && len(feed.Domains) >= maxSplitDomains {
			continue
		}
		entry.Evidence = d.Evidence
		entry.Count++
		entry.LastSeen = now
		feed.Domains[domain] = entry
		added++
	}
	if added == 0 {
		http.Error(w, "nothing usable", http.StatusBadRequest)
		return
	}
	feed.Updated = now
	if err := s.saveFeed(feed); err != nil {
		http.Error(w, "could not store", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) apiSeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if !validSplitNetwork(network) {
		http.Error(w, "bad network", http.StatusBadRequest)
		return
	}
	s.feedMu.Lock()
	feed := s.loadFeed(network)
	s.feedMu.Unlock()

	type seedEntry struct {
		Domain   string `json:"domain"`
		Evidence string `json:"evidence"`
		Count    int    `json:"count"`
	}
	out := struct {
		Version int         `json:"version"`
		Network string      `json:"network"`
		Domains []seedEntry `json:"domains"`
	}{Version: 1, Network: network}
	names := make([]string, 0, len(feed.Domains))
	for domain := range feed.Domains {
		names = append(names, domain)
	}
	sort.Strings(names)
	for _, domain := range names {
		entry := feed.Domains[domain]
		out.Domains = append(out.Domains, seedEntry{Domain: domain, Evidence: entry.Evidence, Count: entry.Count})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// adminSplit is a read-only view of the merged feeds and counters.
func (s *server) adminSplit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	entries, _ := os.ReadDir(s.splitDir())
	var b strings.Builder
	b.WriteString(`<h1>Split feed</h1><p>Domains reported blocked per network. No client identifiers are stored.</p>`)
	if len(entries) == 0 {
		b.WriteString(`<p class="muted">No reports yet.</p>`)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.splitDir(), entry.Name()))
		if err != nil {
			continue
		}
		var feed networkFeed
		if err := json.Unmarshal(data, &feed); err != nil {
			continue
		}
		names := make([]string, 0, len(feed.Domains))
		for domain := range feed.Domains {
			names = append(names, domain)
		}
		sort.Strings(names)
		fmt.Fprintf(&b, `<h2>%s <span class="muted">(%d domains, updated %s)</span></h2>`,
			template.HTMLEscapeString(feed.Network), len(names), template.HTMLEscapeString(feed.Updated))
		b.WriteString(`<table><thead><tr><th>Domain</th><th>Evidence</th><th>Reports</th><th>Last seen</th></tr></thead><tbody>`)
		for i, domain := range names {
			if i >= 200 {
				fmt.Fprintf(&b, `<tr><td colspan="4" class="muted">and %d more</td></tr>`, len(names)-i)
				break
			}
			entry := feed.Domains[domain]
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>`,
				template.HTMLEscapeString(domain), template.HTMLEscapeString(entry.Evidence),
				entry.Count, template.HTMLEscapeString(entry.LastSeen))
		}
		b.WriteString(`</tbody></table>`)
	}
	s.render(w, true, "Split feed", b.String())
}
