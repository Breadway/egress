package netid

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record is one saved network identity. Signals are hashes only; the name is
// the user-facing SSID and is never sent without the user's knowledge.
type Record struct {
	ID          string            `json:"id"`
	Name        string            `json:"name,omitempty"`
	Signals     map[string]string `json:"signals"`
	Fingerprint string            `json:"fingerprint"`
	Aliases     []string          `json:"aliases,omitempty"`
	Probes      []Probe           `json:"probes,omitempty"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	Confidence  float64           `json:"confidence"`
}

// Probe is a domain whose expected state was observed on this network. It is
// used to verify a fuzzy match before switching to the saved profile.
type Probe struct {
	Domain  string `json:"domain"`
	Blocked bool   `json:"blocked"`
}

type storeFile struct {
	Version  int      `json:"version"`
	Networks []Record `json:"networks"`
}

// Store persists network identities in one JSON file.
type Store struct {
	mu   sync.Mutex
	path string
	data storeFile
}

// Open loads the store, creating an empty one when the file is absent.
func Open(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "networks.json"), data: storeFile{Version: 1}}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &s.data); err != nil {
		return nil, err
	}
	if s.data.Version == 0 {
		s.data.Version = 1
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, append(data, '\n'), 0600)
}

// Records returns a copy of the saved records.
func (s *Store) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, len(s.data.Networks))
	copy(out, s.data.Networks)
	return out
}

func (s *Store) byIDLocked(id string) (int, bool) {
	for i := range s.data.Networks {
		if s.data.Networks[i].ID == id {
			return i, true
		}
	}
	for i := range s.data.Networks {
		for _, alias := range s.data.Networks[i].Aliases {
			if alias == id {
				return i, true
			}
		}
	}
	return -1, false
}

// VerifyFunc is the safety gate for a fuzzy match. The default checks the
// anchors and portal fingerprint. A caller can add active probes.
type VerifyFunc func(rec Record, raw Raw, sig Signals) bool

// DefaultVerify accepts a candidate only when a strong anchor matches and, for
// a shared SSID, a DNS suffix or gateway MAC also matched. The same rule keeps
// two sites with the same SSID apart.
func DefaultVerify(rec Record, raw Raw, sig Signals) bool {
	anchor := false
	for kind, h := range sig.Hashes {
		if !strongAnchor(kind) {
			continue
		}
		if rec.Signals[kind] == h {
			anchor = true
		}
	}
	ssid := sig.Hashes[KindSSID]
	savedSSID := rec.Signals[KindSSID]

	// Two different names with different gateways are different networks, even
	// when a generic DNS suffix (lan, home, an ISP domain) is shared. A renamed
	// SSID on the same gateway still merges, which is what a campus or router
	// rename looks like.
	if ssid != "" && savedSSID != "" && ssid != savedSSID {
		mac := sig.Hashes[KindGatewayMAC]
		return mac != "" && rec.Signals[KindGatewayMAC] == mac
	}

	if !anchor {
		return false
	}
	if ssid != "" && savedSSID == ssid {
		suffix := sig.Hashes[KindDNSSuffix] != "" && rec.Signals[KindDNSSuffix] == sig.Hashes[KindDNSSuffix]
		mac := sig.Hashes[KindGatewayMAC] != "" && rec.Signals[KindGatewayMAC] == sig.Hashes[KindGatewayMAC]
		if !suffix && !mac {
			// With neither separator there is no way to tell two sites apart.
			// Keep the SSID as a low-confidence match rather than creating a
			// duplicate network on every DHCP change.
			if rec.Signals[KindDNSSuffix] != "" || rec.Signals[KindGatewayMAC] != "" {
				return false
			}
		}
	}
	// The captive fingerprint is deliberately not a veto: a portal page and
	// its post-login redirect hash differently, so a mismatch is normal on
	// the same network. It only contributes to the score.
	return true
}

// Resolve maps the current signals to a saved identity, creating one when no
// candidate passes verification. Aliases are old keys or IDs that should still
// map to the same network, for example the gateway-keyed names from before this
// identity existed.
func (s *Store) Resolve(raw Raw, aliases []string, verify VerifyFunc) (Record, error) {
	if verify == nil {
		verify = DefaultVerify
	}
	sig := Build(raw)
	fingerprint := sig.Fingerprint()
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	// An exact fingerprint over every observed signal is definitive. Check it
	// before the canonical ID so a changed weak signal (a new DHCP server or
	// gateway IP) can still match, and so a probe outage cannot split a
	// network whose whole signal set is identical.
	for i := range s.data.Networks {
		rec := &s.data.Networks[i]
		if rec.Fingerprint != "" && rec.Fingerprint == fingerprint && DefaultVerify(*rec, raw, sig) {
			s.updateLocked(rec, sig, "", aliases, now, 1.0)
			return *rec, s.saveLocked()
		}
	}

	// An exact canonical ID is the next strongest match. The strong anchors
	// are identical, so active probes are not needed here.
	if id := sig.CanonicalID(); id != "" {
		if i, ok := s.byIDLocked(id); ok {
			rec := &s.data.Networks[i]
			if DefaultVerify(*rec, raw, sig) {
				s.updateLocked(rec, sig, id, aliases, now, 1.0)
				return *rec, s.saveLocked()
			}
		}
	}
	for _, alias := range aliases {
		if i, ok := s.byIDLocked(alias); ok {
			rec := &s.data.Networks[i]
			if aliasVerify(*rec, sig) {
				s.updateLocked(rec, sig, "", aliases, now, 0.8)
				return *rec, s.saveLocked()
			}
		}
	}

	// Fuzzy match: highest weighted score with a strong anchor and the
	// same-SSID guard in DefaultVerify. The exact fingerprint bonus keeps a
	// stale LastSeen from winning a tie. Active probes run once per candidate,
	// best first, so a probe that contradicts a saved profile falls through
	// instead of scanning every record.
	type candidate struct {
		rec   *Record
		score float64
	}
	var candidates []candidate
	for i := range s.data.Networks {
		rec := &s.data.Networks[i]
		score := sig.Score(rec.Signals)
		if rec.Fingerprint != "" && rec.Fingerprint == fingerprint {
			score += 10
		}
		if score < 3 || !DefaultVerify(*rec, raw, sig) {
			continue
		}
		candidates = append(candidates, candidate{rec: rec, score: score})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].rec.LastSeen.After(candidates[j].rec.LastSeen)
	})
	for _, c := range candidates {
		if !verify(*c.rec, raw, sig) {
			continue
		}
		s.updateLocked(c.rec, sig, sig.CanonicalID(), aliases, now, 0.7)
		return *c.rec, s.saveLocked()
	}

	id := sig.CanonicalID()
	if id == "" {
		id = NewID()
	}
	rec := Record{
		ID:          id,
		Name:        networkName(raw),
		Signals:     sig.Hashes,
		Fingerprint: sig.Fingerprint(),
		Aliases:     dedupe(aliases),
		FirstSeen:   now,
		LastSeen:    now,
		Confidence:  confidence(sig),
	}
	s.data.Networks = append(s.data.Networks, rec)
	if err := s.saveLocked(); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func (s *Store) updateLocked(rec *Record, sig Signals, canonical string, aliases []string, now time.Time, confidence float64) {
	// Merge rather than replace. One failed ARP or DHCP read must not erase a
	// strong anchor that still separates this network from another site.
	if rec.Signals == nil {
		rec.Signals = map[string]string{}
	}
	for kind, hash := range sig.Hashes {
		if hash != "" {
			rec.Signals[kind] = hash
		}
	}
	rec.Fingerprint = sig.Fingerprint()
	rec.LastSeen = now
	if rec.FirstSeen.IsZero() {
		rec.FirstSeen = now
	}
	rec.Confidence = confidence
	rec.Aliases = dedupe(append(rec.Aliases, aliases...))
	if canonical != "" && canonical != rec.ID {
		rec.Aliases = dedupe(append(rec.Aliases, canonical))
	}
}

// SetProbes records active expectations learned from the split profile. The
// next resolve can use them to verify a fuzzy match.
func (s *Store) SetProbes(id string, probes []Probe) error {
	if len(probes) > 8 {
		probes = probes[:8]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.byIDLocked(id)
	if !ok {
		return errors.New("network not found")
	}
	s.data.Networks[i].Probes = append([]Probe(nil), probes...)
	return s.saveLocked()
}

// ProbeVerify wraps DefaultVerify with the saved block expectations. A probe
// callback returns whether the domain is blocked now and whether the answer is
// conclusive. All conclusive answers must agree up to two; with three or more
// expectations checked, two matches are enough so one moved or flaky domain
// does not block the merge.
func ProbeVerify(probe func(domain string) (blocked, ok bool)) VerifyFunc {
	return func(rec Record, raw Raw, sig Signals) bool {
		if !DefaultVerify(rec, raw, sig) {
			return false
		}
		if probe == nil || len(rec.Probes) == 0 {
			return true
		}
		checked, matched := 0, 0
		for _, p := range rec.Probes {
			blocked, ok := probe(p.Domain)
			if !ok {
				continue
			}
			checked++
			if blocked == p.Blocked {
				matched++
			}
			if checked == 3 {
				break
			}
		}
		if checked == 0 {
			return true
		}
		need := 2
		if checked < need {
			need = checked
		}
		return matched >= need
	}
}

// aliasVerify accepts a record found through an exact old key. The key already
// names this gateway (and the SSID when it was readable), so a temporarily
// unreadable signal must not break the migration. It still refuses when both
// sides know an SSID and they disagree.
func aliasVerify(rec Record, sig Signals) bool {
	a, b := rec.Signals[KindSSID], sig.Hashes[KindSSID]
	if a != "" && b != "" && a != b {
		return false
	}
	return true
}

func networkName(raw Raw) string {
	if raw.SSID != "" {
		return raw.SSID
	}
	return "Wired network"
}

func confidence(sig Signals) float64 {
	if sig.Hashes[KindGatewayMAC] != "" || sig.Hashes[KindDNSSuffix] != "" {
		return 0.9
	}
	if sig.Hashes[KindSSID] != "" {
		return 0.6
	}
	return 0.3
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
