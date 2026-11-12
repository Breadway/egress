package main

import (
	"crypto/sha256"
	"encoding/hex"
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

// splitNetworkPepper separates the SSID hash from a bare SHA-256. It is not a
// secret: an SSID has a small search space, so this is obfuscation of the
// network name, not proof of secrecy.
const splitNetworkPepper = "egress-split-v1:"

const (
	splitFeedVersion = 2
	splitEntryTTL    = 30 * 24 * time.Hour
)

var (
	splitNetworkIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	splitProtocols   = map[string]bool{"udp": true, "tcp": true, "icmp": true, "dns": true, "quic": true}
	splitStates      = map[string]bool{"blocked": true, "allowed": true}
	splitProtoStates = map[string]bool{"ok": true, "blocked": true, "unknown": true}

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

// splitDomainReport is one device's observation about one domain. State is
// "blocked" or "allowed"; Final marks the answer to a recheck or verification
// the server asked for while resolving a conflict.
type splitDomainReport struct {
	Domain   string `json:"domain"`
	State    string `json:"state,omitempty"`
	Evidence string `json:"evidence"`
	Final    bool   `json:"final,omitempty"`
}

// splitProtocolReport is one device's observation about outbound protocol
// reachability on this network.
type splitProtocolReport struct {
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Evidence string `json:"evidence"`
}

type splitReport struct {
	Device    string                `json:"device"`
	Network   string                `json:"network,omitempty"`
	NetworkID string                `json:"network_id,omitempty"`
	Domains   []splitDomainReport   `json:"domains"`
	Protocols []splitProtocolReport `json:"protocols,omitempty"`
}

// feedEntry holds the merged state of one domain. Block wins a conflict: a
// single blocked observation among the verification answers keeps the domain
// blocked.
type feedEntry struct {
	State           string   `json:"state"` // blocked or allowed
	Evidence        string   `json:"evidence"`
	Count           int      `json:"count"`
	LastSeen        string   `json:"last_seen"`
	AllowedEvidence string   `json:"allowed_evidence,omitempty"`
	AllowedSeen     string   `json:"allowed_seen,omitempty"`
	Contested       bool     `json:"contested,omitempty"`
	ContestSince    string   `json:"contest_since,omitempty"`
	RecheckAsked    bool     `json:"recheck_asked,omitempty"`
	VerifyAsked     bool     `json:"verify_asked,omitempty"`
	Finals          []string `json:"finals,omitempty"`
}

// protocolEntry is the merged reachability of one outbound protocol.
type protocolEntry struct {
	State    string `json:"state"` // ok, blocked, or unknown
	Evidence string `json:"evidence"`
	Count    int    `json:"count"`
	LastSeen string `json:"last_seen"`
}

type networkFeed struct {
	Version   int                      `json:"version"`
	NetworkID string                   `json:"network_id"`
	Updated   string                   `json:"updated"`
	Domains   map[string]feedEntry     `json:"domains"`
	Protocols map[string]protocolEntry `json:"protocols,omitempty"`
}

func (s *server) splitDir() string { return filepath.Join(s.state, "split") }

// networkID returns the hashed network key. Legacy plaintext names are hashed
// on arrival so the server never stores the SSID itself.
func networkID(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if splitNetworkIDRe.MatchString(raw) {
		return raw
	}
	sum := sha256.Sum256([]byte(splitNetworkPepper + raw))
	return hex.EncodeToString(sum[:])[:32]
}

func (s *server) feedPath(id string) string {
	return filepath.Join(s.splitDir(), id+".json")
}

func (s *server) loadFeed(id string) networkFeed {
	feed := networkFeed{Version: splitFeedVersion, NetworkID: id,
		Domains: map[string]feedEntry{}, Protocols: map[string]protocolEntry{}}
	data, err := os.ReadFile(s.feedPath(id))
	if err != nil {
		return feed
	}
	if err := json.Unmarshal(data, &feed); err != nil {
		return networkFeed{Version: splitFeedVersion, NetworkID: id,
			Domains: map[string]feedEntry{}, Protocols: map[string]protocolEntry{}}
	}
	if feed.Domains == nil {
		feed.Domains = map[string]feedEntry{}
	}
	if feed.Protocols == nil {
		feed.Protocols = map[string]protocolEntry{}
	}
	feed.Version = splitFeedVersion
	feed.NetworkID = id
	// Drop stale entries: a block that nobody has seen for a month is a
	// different network or a different censorship regime.
	cutoff := time.Now().UTC().Add(-splitEntryTTL).Format(time.RFC3339)
	for domain, entry := range feed.Domains {
		if entry.LastSeen < cutoff {
			delete(feed.Domains, domain)
		}
	}
	for proto, entry := range feed.Protocols {
		if entry.LastSeen < cutoff {
			delete(feed.Protocols, proto)
		}
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
	path := s.feedPath(feed.NetworkID)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// validSplitNetwork accepts a hashed network id, or a legacy plaintext name
// which callers hash before use.
func validSplitNetwork(network string) bool {
	network = strings.TrimSpace(network)
	if splitNetworkIDRe.MatchString(network) {
		return true
	}
	return len(network) >= 1 && len(network) <= 120
}

func validSplitDomain(domain string) bool {
	return len(domain) <= 253 && splitDomainRe.MatchString(domain)
}

func containsState(states []string, want string) bool {
	for _, s := range states {
		if s == want {
			return true
		}
	}
	return false
}

// apiBlockedReport merges one device's observations. Blocked and allowed
// observations about the same domain contest it; the blocked device and the
// allowing device are then asked to re-check, and any blocked answer keeps the
// domain blocked.
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
	raw := rep.NetworkID
	if raw == "" {
		raw = rep.Network
	}
	if rep.Device == "" || !validSplitNetwork(raw) {
		http.Error(w, "bad device or network", http.StatusBadRequest)
		return
	}
	if len(rep.Domains) == 0 && len(rep.Protocols) == 0 {
		http.Error(w, "nothing to report", http.StatusBadRequest)
		return
	}

	s.feedMu.Lock()
	defer s.feedMu.Unlock()
	feed := s.loadFeed(networkID(raw))
	now := time.Now().UTC().Format(time.RFC3339)
	added := 0

	if len(rep.Domains) > maxSplitReport {
		rep.Domains = rep.Domains[:maxSplitReport]
	}
	for _, d := range rep.Domains {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.Domain)), ".")
		if !validSplitDomain(domain) || !splitEvidence[d.Evidence] {
			continue
		}
		state := strings.ToLower(strings.TrimSpace(d.State))
		if state == "" {
			state = "blocked"
		}
		if !splitStates[state] {
			continue
		}
		entry, ok := feed.Domains[domain]
		if !ok && len(feed.Domains) >= maxSplitDomains {
			continue
		}
		entry = mergeDomainObservation(entry, state, d.Evidence, d.Final, now)
		feed.Domains[domain] = entry
		added++
	}

	if len(rep.Protocols) > len(splitProtocols) {
		rep.Protocols = rep.Protocols[:len(splitProtocols)]
	}
	for _, p := range rep.Protocols {
		proto := strings.ToLower(strings.TrimSpace(p.Protocol))
		state := strings.ToLower(strings.TrimSpace(p.State))
		if !splitProtocols[proto] || !splitProtoStates[state] {
			continue
		}
		entry := feed.Protocols[proto]
		entry.State = state
		entry.Evidence = truncateText(p.Evidence, 40)
		entry.Count++
		entry.LastSeen = now
		feed.Protocols[proto] = entry
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

// mergeDomainObservation applies the conflict rules for one observation.
func mergeDomainObservation(entry feedEntry, state, evidence string, final bool, now string) feedEntry {
	if entry.State == "" {
		entry.State = state
	}
	switch state {
	case "blocked":
		entry.State = "blocked"
		entry.Evidence = evidence
		entry.Count++
		entry.LastSeen = now
		if entry.Contested {
			// Ask the blocked side to confirm once the allowing side has
			// re-checked; either answer is evidence, but only a block wins.
			if entry.RecheckAsked || entry.VerifyAsked {
				entry.VerifyAsked = true
			}
		}
		if final {
			entry.Finals = append(entry.Finals, "blocked")
			entry.State = "blocked"
			entry.Contested = false
			entry.RecheckAsked = false
			entry.VerifyAsked = false
		}
	case "allowed":
		entry.AllowedEvidence = evidence
		entry.AllowedSeen = now
		if entry.Count == 0 {
			entry.State = "allowed"
			entry.LastSeen = now
			break
		}
		if !entry.Contested {
			entry.Contested = true
			entry.ContestSince = now
		}
		// The device that says allowed re-checks first.
		entry.RecheckAsked = true
		if final {
			entry.Finals = append(entry.Finals, "allowed")
			entry.RecheckAsked = false
			if !containsState(entry.Finals, "blocked") {
				entry.State = "allowed"
				entry.Contested = false
				entry.VerifyAsked = false
			}
		}
	}
	return entry
}

// apiSeed returns the merged table for one network, including the protocol
// picture and the domains this device should re-check or verify.
func (s *server) apiSeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw := strings.TrimSpace(r.URL.Query().Get("n"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("network"))
	}
	if !validSplitNetwork(raw) {
		http.Error(w, "bad network", http.StatusBadRequest)
		return
	}
	id := networkID(raw)
	s.feedMu.Lock()
	feed := s.loadFeed(id)
	s.feedMu.Unlock()

	type seedDomain struct {
		Domain    string `json:"domain"`
		Evidence  string `json:"evidence"`
		Count     int    `json:"count"`
		Contested bool   `json:"contested,omitempty"`
		Recheck   bool   `json:"recheck,omitempty"`
		Verify    bool   `json:"verify,omitempty"`
	}
	type seedProtocol struct {
		Protocol string `json:"protocol"`
		State    string `json:"state"`
		Count    int    `json:"count"`
	}
	out := struct {
		Version   int            `json:"version"`
		NetworkID string         `json:"network_id"`
		Domains   []seedDomain   `json:"domains"`
		Protocols []seedProtocol `json:"protocols,omitempty"`
	}{Version: splitFeedVersion, NetworkID: id}

	names := make([]string, 0, len(feed.Domains))
	for domain := range feed.Domains {
		names = append(names, domain)
	}
	sort.Strings(names)
	for _, domain := range names {
		entry := feed.Domains[domain]
		if entry.State != "blocked" {
			continue
		}
		out.Domains = append(out.Domains, seedDomain{
			Domain: domain, Evidence: entry.Evidence, Count: entry.Count,
			Contested: entry.Contested, Recheck: entry.RecheckAsked, Verify: entry.VerifyAsked,
		})
	}
	protos := make([]string, 0, len(feed.Protocols))
	for proto := range feed.Protocols {
		protos = append(protos, proto)
	}
	sort.Strings(protos)
	for _, proto := range protos {
		entry := feed.Protocols[proto]
		out.Protocols = append(out.Protocols, seedProtocol{Protocol: proto, State: entry.State, Count: entry.Count})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// adminSplit is a read-only view of the merged feeds: blocked domains,
// conflicts and the protocol picture per network.
func (s *server) adminSplit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	entries, _ := os.ReadDir(s.splitDir())
	var b strings.Builder
	b.WriteString(`<h1>Split feed</h1><p>Per-network tables keyed by a hashed SSID. No client identifiers or plaintext network names are stored. Block wins a conflict: one blocked verification keeps the domain blocked.</p>`)
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
		contested := 0
		for _, domain := range names {
			if feed.Domains[domain].Contested {
				contested++
			}
		}
		fmt.Fprintf(&b, `<h2>%s <span class="muted">(%d domains, %d contested, updated %s)</span></h2>`,
			template.HTMLEscapeString(feed.NetworkID), len(names), contested, template.HTMLEscapeString(feed.Updated))
		if len(feed.Protocols) > 0 {
			protos := make([]string, 0, len(feed.Protocols))
			for proto := range feed.Protocols {
				protos = append(protos, proto)
			}
			sort.Strings(protos)
			b.WriteString(`<p class="muted">Protocols: `)
			for i, proto := range protos {
				if i > 0 {
					b.WriteString(", ")
				}
				fmt.Fprintf(&b, `%s %s`, template.HTMLEscapeString(proto), template.HTMLEscapeString(feed.Protocols[proto].State))
			}
			b.WriteString(`</p>`)
		}
		b.WriteString(`<table><thead><tr><th>Domain</th><th>State</th><th>Evidence</th><th>Reports</th><th>Contested</th><th>Last seen</th></tr></thead><tbody>`)
		for i, domain := range names {
			if i >= 200 {
				fmt.Fprintf(&b, `<tr><td colspan="6" class="muted">and %d more</td></tr>`, len(names)-i)
				break
			}
			entry := feed.Domains[domain]
			contested := ""
			if entry.Contested {
				contested = "yes"
			}
			fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>`,
				template.HTMLEscapeString(domain), template.HTMLEscapeString(entry.State),
				template.HTMLEscapeString(entry.Evidence), entry.Count, contested,
				template.HTMLEscapeString(entry.LastSeen))
		}
		b.WriteString(`</tbody></table>`)
	}
	s.renderNav(w, true, "admin", "Split feed", b.String())
}
