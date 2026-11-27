// Package exitroute decides which destination prefixes leave through which
// exit, including the cloud exit.
//
// A site the local network filters is routed into the tunnel. The tunnel exits
// at Aegis by default, whose address is a cloud one, and some sites refuse
// cloud addresses with a block page. An operator can enroll other hosts as
// exits (a home connection, a second line, a friend's box). The learner asks
// every blocked site over the cloud exit and, when that is refused, through
// each enrolled exit in priority order. The prefixes of a site are routed to
// the first exit that serves it, and the cloud exit is retried every cycle so
// a prefix goes back the moment the cloud works again.
//
// Nothing is hardcoded: candidates come from the shared block table the fleet
// reports, and exits come from a registry the operator writes.
package exitroute

import (
	"crypto/x509"
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

// Exit is one enrolled exit host.
type Exit struct {
	ID          string `json:"id"`
	Label       string `json:"label,omitempty"`
	PubKey      string `json:"pubkey"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority,omitempty"`
	MaxPrefixes int    `json:"max_prefixes,omitempty"`
	Host        string `json:"host,omitempty"`
	// Address is the exit's tunnel address on the hub, for example
	// 10.99.0.2. The router keeps it in the peer's allowed IPs so the hub
	// can DNAT a destination to the exit itself, not only to a prefix the
	// exit carries.
	Address string `json:"address,omitempty"`
	// Network is the exit's own network id when it also runs as a client.
	// The learner skips it for domains that network reports blocked.
	Network string `json:"network,omitempty"`
	Note    string `json:"note,omitempty"`
	// Direct marks an exit that clients reach themselves rather than through
	// Aegis. It is not a peer of wg0, so the hub router must never assign
	// prefixes to it; the fleet learns its endpoint from the feed instead.
	Direct   bool   `json:"direct,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Path     string `json:"path,omitempty"`
}

// Registry is the operator's exit list.
type Registry struct {
	Version int    `json:"version"`
	Exits   []Exit `json:"exits"`
}

// LoadRegistry reads the exit registry. A missing file is an empty registry:
// the cloud exit still works, and blocked names are simply unserved.
func LoadRegistry(path string) (Registry, error) {
	reg := Registry{Version: 1}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return reg, nil
		}
		return reg, err
	}
	if err := json.Unmarshal(data, &reg); err != nil {
		return reg, err
	}
	for i := range reg.Exits {
		e := &reg.Exits[i]
		if e.ID == "" {
			e.ID = e.Label
		}
		if e.Priority == 0 {
			e.Priority = 100
		}
		if e.MaxPrefixes <= 0 {
			e.MaxPrefixes = 200
		}
	}
	return reg, nil
}

// SaveRegistry writes the registry atomically, keeping it readable for the
// web admin and writable only by root.
func SaveRegistry(path string, reg Registry) error {
	reg.Version = 1
	sort.Slice(reg.Exits, func(i, j int) bool {
		if reg.Exits[i].Priority != reg.Exits[j].Priority {
			return reg.Exits[i].Priority < reg.Exits[j].Priority
		}
		return reg.Exits[i].ID < reg.Exits[j].ID
	})
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// EnabledExits returns the enabled exits in priority order.
func EnabledExits(reg Registry) []Exit {
	out := make([]Exit, 0, len(reg.Exits))
	for _, e := range reg.Exits {
		// A direct exit is reached by clients, not by this router: it has no
		// wg0 peer here, so assigning prefixes to it would blackhole them.
		if e.Enabled && !e.Direct {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Site states.
const (
	SiteCloud    = "cloud"
	SiteExit     = "exit"
	SiteUnserved = "unserved"
)

// Site is the learned state of one blocked domain.
type Site struct {
	Domain   string    `json:"domain"`
	Prefixes []string  `json:"prefixes"`
	Cloud    int       `json:"cloud"`
	CloudErr string    `json:"cloud_error,omitempty"`
	Exit     string    `json:"exit,omitempty"`
	State    string    `json:"state"`
	Verified time.Time `json:"verified"`
	Expires  time.Time `json:"expires,omitempty"`
}

// State is the learner's persisted picture.
type State struct {
	Updated     time.Time         `json:"updated"`
	Sites       map[string]Site   `json:"sites"`
	Assignments map[string]string `json:"assignments"` // prefix -> exit id
}

// ExitStatus is one exit's live health, published for the admin page and the
// fleet feed.
type ExitStatus struct {
	ID        string `json:"id"`
	Label     string `json:"label,omitempty"`
	Enabled   bool   `json:"enabled"`
	Healthy   bool   `json:"healthy"`
	Handshake int64  `json:"handshake,omitempty"`
	Prefixes  int    `json:"prefixes"`
	Sites     int    `json:"sites"`
	Error     string `json:"error,omitempty"`
}

// Status is the learner's report. It carries no secrets and is world-readable
// so the web admin can show it.
type Status struct {
	Updated     time.Time         `json:"updated"`
	Sites       map[string]Site   `json:"sites"`
	Assignments map[string]string `json:"assignments"`
	Exits       []ExitStatus      `json:"exits"`
	Unserved    []string          `json:"unserved"`
	AllDown     bool              `json:"all_down,omitempty"`
}

// ProbeResult is one path's answer for a site.
type ProbeResult struct {
	// Handshake is set when TLS completed, or when the handshake failed only
	// because the address does not serve that name. Either way the network
	// path reached the site.
	Handshake bool
	// Status is the HTTP status, zero when the server closed without a reply.
	Status int
	Err    error
}

// Works reports whether the path reaches the site. A site may close the
// connection after the handshake, as file-only CDN hosts do for "/", and that
// still means the path works. A refusal is a failed handshake (an SNI filter,
// a stall) or an explicit block.
func (r ProbeResult) Works() bool {
	if !r.Handshake {
		return false
	}
	switch r.Status {
	case 403, 451, 429:
		return false
	}
	return true
}

func nameMismatch(err error) bool {
	var invalid x509.CertificateInvalidError
	var host x509.HostnameError
	var unknown x509.UnknownAuthorityError
	return errors.As(err, &invalid) || errors.As(err, &host) || errors.As(err, &unknown)
}

func served(status int) bool { return status >= 200 && status < 400 }

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

// PrefixesFor turns addresses into the /24 blocks that are safe to route. A
// /24 rather than a /32 keeps a Fastly or Cloudflare name working when it
// resolves to a different address on the next lookup, and the special-use
// guard keeps a poisoned answer from touching the local network.
func PrefixesFor(ips []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ips))
	for _, raw := range ips {
		ip := net.ParseIP(strings.TrimSpace(raw)).To4()
		if ip == nil || special(ip) {
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

// Candidate is one blocked domain from the shared table.
type Candidate struct {
	Domain   string
	Evidence string
	Count    int
}

// Candidates reads every network's shared block table and returns the domains
// the fleet says are blocked anywhere. Duplicates collapse to the most recent
// evidence.
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

// LoadState reads the persisted state.
func LoadState(path string) (State, error) {
	state := State{Sites: map[string]Site{}, Assignments: map[string]string{}}
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
	if state.Sites == nil {
		state.Sites = map[string]Site{}
	}
	if state.Assignments == nil {
		state.Assignments = map[string]string{}
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

// SaveStatus publishes the learner's report.
func SaveStatus(path string, status Status) error {
	status.Updated = time.Now().UTC()
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadStatus reads the router's published status.
func LoadStatus(path string) (Status, error) {
	var status Status
	data, err := os.ReadFile(path)
	if err != nil {
		return status, err
	}
	if err := json.Unmarshal(data, &status); err != nil {
		return status, err
	}
	if status.Sites == nil {
		status.Sites = map[string]Site{}
	}
	if status.Assignments == nil {
		status.Assignments = map[string]string{}
	}
	return status, nil
}

// Unserved returns the blocked domains no exit serves, sorted.
func (s Status) UnservedDomains() []string {
	out := make([]string, 0, len(s.Sites))
	for domain, site := range s.Sites {
		if site.State == SiteUnserved {
			out = append(out, domain)
		}
	}
	sort.Strings(out)
	return out
}
