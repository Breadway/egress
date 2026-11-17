// Package exitroute decides which destination prefixes must leave through the
// residential exit instead of the cloud exit.
//
// A site the local network filters is routed into the tunnel. The tunnel then
// exits at Aegis, whose address is a cloud one, and some sites refuse cloud
// addresses with a block page. The learner asks the same site over both exits:
// when the cloud exit is refused and the home exit is served, the prefixes the
// site resolves to are routed through the home exit. Nothing is hardcoded: the
// candidate set comes from the shared block table the fleet reports, and a
// prefix stops using the home exit as soon as the cloud exit works again.
package exitroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Entry is one learned prefix.
type Entry struct {
	Prefix   string    `json:"prefix"`
	Domain   string    `json:"domain"`
	Cloud    int       `json:"cloud"`
	Home     int       `json:"home"`
	Verified time.Time `json:"verified"`
	Expires  time.Time `json:"expires"`
}

// State is the learner's persisted picture.
type State struct {
	Updated time.Time        `json:"updated"`
	Entries map[string]Entry `json:"entries"`
}

// Observation is one site compared over both exits. A status of zero means the
// request did not produce an HTTP response.
type Observation struct {
	Domain   string
	Prefixes []string
	Cloud    int
	CloudErr string
	Home     int
	HomeErr  string
}

// ExitBlocked reports whether a site serves the home exit while refusing the
// cloud one. A site that fails over both exits is not the exit's fault, and a
// site that answers the cloud exit is left alone.
func ExitBlocked(o Observation) bool {
	if o.Home == 0 || o.Home >= 400 {
		return false
	}
	if o.Cloud == 0 {
		// No HTTP answer at all over the cloud exit (a reset, a stall or a
		// refused TLS session) while the home exit is served is the strongest
		// signal there is.
		return o.CloudErr != ""
	}
	switch o.Cloud {
	case 403, 451, 429:
		return true
	}
	return false
}

// EntryFor builds the entry a positive observation produces.
func EntryFor(o Observation, now time.Time, ttl time.Duration) Entry {
	return Entry{
		Domain:   o.Domain,
		Cloud:    o.Cloud,
		Home:     o.Home,
		Verified: now.UTC(),
		Expires:  now.Add(ttl).UTC(),
	}
}

var specialUse = []*net.IPNet{
	mustCIDR("0.0.0.0/8"),
	mustCIDR("10.0.0.0/8"),
	mustCIDR("100.64.0.0/10"),
	mustCIDR("127.0.0.0/8"),
	mustCIDR("169.254.0.0/16"),
	mustCIDR("172.16.0.0/12"),
	mustCIDR("192.168.0.0/16"),
	mustCIDR("224.0.0.0/4"),
	mustCIDR("240.0.0.0/4"),
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// PrefixesFor turns addressed into the /24 blocks that are safe to route. A
// /24 rather than a /32 keeps a Fastly or Cloudflare name working when it
// resolves to a different address on the next lookup, and the special-use
// guard keeps a poisoned answer from touching the local network.
func PrefixesFor(ips []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ips))
	for _, raw := range ips {
		ip := net.ParseIP(strings.TrimSpace(raw)).To4()
		if ip == nil {
			continue
		}
		if special(ip) {
			continue
		}
		prefix := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
		if seen[prefix] {
			continue
		}
		seen[prefix] = true
		out = append(out, prefix)
	}
	sort.Strings(out)
	return out
}

func special(ip net.IP) bool {
	for _, n := range specialUse {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Desired merges the entries that are still fresh into the prefix set.
func Desired(state State, now time.Time, limit int) []string {
	prefixes := make([]string, 0, len(state.Entries))
	for prefix, entry := range state.Entries {
		if now.After(entry.Expires) {
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	if limit > 0 && len(prefixes) > limit {
		// Keep the most recently verified when the cap is hit.
		sort.Slice(prefixes, func(i, j int) bool {
			return state.Entries[prefixes[i]].Verified.After(state.Entries[prefixes[j]].Verified)
		})
		prefixes = prefixes[:limit]
		sort.Strings(prefixes)
	}
	return prefixes
}

// Reconcile compares what should be routed with what is routed.
func Reconcile(desired, applied []string) (add, remove []string) {
	want := make(map[string]bool, len(desired))
	for _, p := range desired {
		want[p] = true
	}
	have := make(map[string]bool, len(applied))
	for _, p := range applied {
		have[p] = true
	}
	for p := range want {
		if !have[p] {
			add = append(add, p)
		}
	}
	for p := range have {
		if !want[p] {
			remove = append(remove, p)
		}
	}
	sort.Strings(add)
	sort.Strings(remove)
	return add, remove
}

// Prune drops expired entries.
func Prune(state State, now time.Time) {
	for prefix, entry := range state.Entries {
		if now.After(entry.Expires) {
			delete(state.Entries, prefix)
		}
	}
}

// Candidate is one blocked domain from the shared table.
type Candidate struct {
	Domain   string
	Evidence string
	Count    int
}

// Candidates reads every network's shared block table and returns the domains
// the fleet says are blocked here. Duplicates across networks collapse to the
// most recent evidence.
func Candidates(dir string) ([]Candidate, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	byDomain := map[string]Candidate{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var feed struct {
			Domains map[string]struct {
				State    string `json:"state"`
				Evidence string `json:"evidence"`
				Count    int    `json:"count"`
			} `json:"domains"`
		}
		if err := json.Unmarshal(data, &feed); err != nil {
			continue
		}
		for domain, obs := range feed.Domains {
			if obs.State != "blocked" {
				continue
			}
			domain = strings.ToLower(strings.TrimSpace(domain))
			if !plausibleDomain(domain) {
				continue
			}
			prev, ok := byDomain[domain]
			if !ok || obs.Count > prev.Count {
				byDomain[domain] = Candidate{Domain: domain, Evidence: obs.Evidence, Count: obs.Count}
			}
		}
	}
	out := make([]Candidate, 0, len(byDomain))
	for _, c := range byDomain {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

// ExtraDomains reads a plain list of additional candidates, one per line.
func ExtraDomains(path string) ([]Candidate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Candidate
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if domain := strings.ToLower(line); plausibleDomain(domain) {
			out = append(out, Candidate{Domain: domain, Evidence: "manual"})
		}
	}
	return out, nil
}

// plausibleDomain rejects names a probe should never touch.
func plausibleDomain(d string) bool {
	if d == "" || len(d) > 253 || strings.ContainsAny(d, " /:\\") {
		return false
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	if net.ParseIP(d) != nil {
		return false
	}
	if !strings.Contains(d, ".") {
		return false
	}
	switch d {
	case "localhost", "local", "invalid", "test", "example", "onion":
		return false
	}
	return true
}

// LoadState reads the persisted state, returning an empty state when there is
// no file yet.
func LoadState(path string) (State, error) {
	state := State{Entries: map[string]Entry{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if state.Entries == nil {
		state.Entries = map[string]Entry{}
	}
	return state, nil
}

// SaveState writes the state atomically.
func SaveState(path string, state State) error {
	state.Updated = time.Now().UTC()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
