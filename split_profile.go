package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

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

// ProfilePath is the file for one network key.
func ProfilePath(network string) string {
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
	return filepath.Join(ProfileDir(), "split-"+safe+".json")
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
