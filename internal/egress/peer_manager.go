package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"egress/internal/core"
)

// peerPlatform is the runtime peer control both platforms implement.
type peerPlatform interface {
	SetPeer(dev, pubkey, endpoint string, allowed []string) error
	RemovePeer(dev, pubkey string) error
}

// peerConfigPlatform is the Windows shape: the tunnel service owns its peer
// list, so a peer must be written into the config and the service restarted
// once. Linux applies peers at runtime and does not implement this.
type peerConfigPlatform interface {
	EnsureRelayPeer(dev, pubkey, endpoint string, allowed []string) (bool, error)
	RemoveRelayPeer(dev, pubkey string) error
}

type apiPeer struct {
	Label    string `json:"label"`
	PubKey   string `json:"pubkey"`
	IP       string `json:"ip"`
	Endpoint string `json:"endpoint"`
}

type peerLink struct {
	pubkey   string
	ip       string
	endpoint string
	dialable bool

	// present means the peer exists in WireGuard, with no routes by default.
	// A passive peer accepts an inbound handshake and learns the endpoint from
	// it, which is how a device behind the relay gets a direct link: the side
	// with a public address dials, and this side only has to be willing.
	present   bool
	dialing   bool
	dialStart time.Time
	direct    bool
	failures  int

	backoffUntil time.Time
}

const (
	// peerAttemptWindow is how long a dial may take before it is demoted to a
	// passive peer. WireGuard retransmits a handshake every few seconds, so one
	// successful round trip is enough; the window only has to outlast the first
	// retransmission after both sides have the peer configured.
	peerAttemptWindow = 20 * time.Second
	// peerHandshakeStale is when an active link is considered gone. Persistent
	// keepalive rekeys about every two minutes.
	peerHandshakeStale = 4 * time.Minute
)

// peerBackoff grows after repeated failures. A pair on a NAT that cannot punch
// should still retry after a router reboot, without being hammered meanwhile.
func peerBackoff(failures int) time.Duration {
	switch {
	case failures <= 1:
		return time.Minute
	case failures == 2:
		return 5 * time.Minute
	default:
		return 30 * time.Minute
	}
}

// peerManager turns the peer list into direct WireGuard links. It never
// removes the star: the Aegis peer carries 10.88.0.0/24, so a peer with no
// active route, or a passive one, is reached through Aegis automatically.
type peerManager struct {
	plat peerPlatform
	dev  string
	log  *log.Logger
	self string

	// handshake is a variable so tests can drive the state machine without a
	// live WireGuard interface.
	handshake func(dev, pubkey string) (time.Duration, bool)

	mu        sync.Mutex
	links     map[string]*peerLink
	lastCount int
}

func newPeerManager(plat peerPlatform, dev string, logger *log.Logger) *peerManager {
	return &peerManager{
		plat: plat, dev: dev, log: logger, links: map[string]*peerLink{},
		self: devicePubkey(), handshake: handshakeAge,
	}
}

func (m *peerManager) Run(ctx context.Context) {
	if m.self == "" {
		m.log.Printf("peers: no device identity; direct links stay off")
		return
	}
	m.refresh(ctx)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	refresh := time.NewTicker(5 * time.Minute)
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			m.shutdown()
			return
		case <-refresh.C:
			m.refresh(ctx)
		case <-tick.C:
		}
		m.reconcile()
	}
}

// shutdown drops every peer this manager configured so a restart starts from
// the published list rather than a stale mix of links.
func (m *peerManager) shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, link := range m.links {
		if link.present {
			m.removeLocked(link)
		}
		delete(m.links, key)
	}
}

func (m *peerManager) refresh(ctx context.Context) {
	peers, err := fetchPeers(ctx, m.self)
	if err != nil {
		m.log.Printf("peers: %v", err)
		return
	}
	m.setDesired(peers)
	m.mu.Lock()
	count := 0
	for _, link := range m.links {
		if link.dialable {
			count++
		}
	}
	changed := count != m.lastCount
	m.lastCount = count
	m.mu.Unlock()
	if changed {
		m.log.Printf("peers: %d directly dialable peer(s), %d known", count, len(peers))
	}
}

// setDesired is the part of refresh that does not touch the network, split out
// so the state machine can be tested.
func (m *peerManager) setDesired(peers []apiPeer) {
	desired := map[string]apiPeer{}
	for _, p := range peers {
		if p.PubKey == "" || p.PubKey == m.self || p.IP == "" || p.Endpoint == "" {
			continue
		}
		desired[p.PubKey] = p
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, link := range m.links {
		if _, ok := desired[key]; !ok {
			if link.present {
				m.removeLocked(link)
			}
			delete(m.links, key)
		}
	}
	for key, p := range desired {
		link, ok := m.links[key]
		if !ok {
			link = &peerLink{pubkey: key}
			m.links[key] = link
		}
		if link.endpoint != p.Endpoint && link.endpoint != "" {
			// A changed mapping means the old backoff was earned against an
			// address that no longer exists.
			link.backoffUntil = time.Time{}
			link.failures = 0
		}
		link.ip, link.endpoint = p.IP, p.Endpoint
		link.dialable = dialable(p.Endpoint)
	}
}

// dialable rejects addresses that cannot be reached from another machine: the
// loopback the relay produces when a device reaches Aegis through the
// WebSocket tunnel. Those peers are still worth configuring passively, because
// they can dial us.
func dialable(endpoint string) bool {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}
	return host != "" && host != "127.0.0.1" && host != "::1"
}

func (m *peerManager) reconcile() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	// One new configuration write per pass: on Windows each one can restart the
	// tunnel service, and several at once would restart it repeatedly.
	budget := 1
	for _, link := range m.links {
		if !link.present {
			if budget == 0 {
				continue
			}
			if err := m.configure(link, "", nil); err != nil {
				m.log.Printf("peers: %s: %v", link.ip, err)
				link.backoffUntil = now.Add(peerBackoff(link.failures + 1))
				continue
			}
			link.present = true
			budget--
			if !link.dialable {
				continue
			}
		}
		switch {
		case link.direct:
			if age, ok := m.handshake(m.dev, link.pubkey); !ok || age > peerHandshakeStale {
				// Keep the peer and its learned endpoint, drop the route, and
				// let the star carry traffic until a dial succeeds again.
				if err := m.configure(link, "", []string{}); err != nil {
					m.log.Printf("peers: demote %s: %v", link.ip, err)
				}
				link.direct = false
				link.failures++
				link.backoffUntil = now.Add(peerBackoff(link.failures))
				m.log.Printf("peers: %s lost its direct link; back on Aegis", link.ip)
			}
		case link.dialing:
			if now.Sub(link.dialStart) < peerAttemptWindow {
				continue
			}
			if age, ok := m.handshake(m.dev, link.pubkey); ok && age < 2*time.Minute {
				link.dialing = false
				link.direct = true
				link.failures = 0
				promoteEndpoint := ""
				if link.dialable {
					promoteEndpoint = link.endpoint
				}
				if err := m.configure(link, promoteEndpoint, []string{link.ip + "/32"}); err != nil {
					m.log.Printf("peers: activate %s: %v", link.ip, err)
					link.direct = false
				} else {
					m.log.Printf("peers: direct link to %s (%s)", link.ip, link.endpoint)
				}
				continue
			}
			if err := m.configure(link, "", []string{}); err != nil {
				m.log.Printf("peers: demote %s: %v", link.ip, err)
			}
			link.dialing = false
			link.failures++
			link.backoffUntil = now.Add(peerBackoff(link.failures))
			m.log.Printf("peers: %s did not answer directly; back on Aegis", link.ip)
		default:
			if !link.dialable || budget == 0 || now.Before(link.backoffUntil) {
				continue
			}
			if err := m.configure(link, link.endpoint, []string{link.ip + "/32"}); err != nil {
				m.log.Printf("peers: dial %s: %v", link.ip, err)
				link.failures++
				link.backoffUntil = now.Add(peerBackoff(link.failures))
				continue
			}
			link.dialing = true
			link.dialStart = now
			budget--
			m.log.Printf("peers: trying a direct link to %s (%s)", link.ip, link.endpoint)
		}
	}
}

// configure applies a peer state. An empty endpoint leaves the current one
// alone; a nil allowed list leaves the routes alone; an empty non-nil list
// clears them, which is how a link is demoted without losing the learned
// endpoint.
func (m *peerManager) configure(link *peerLink, endpoint string, allowed []string) error {
	if cfg, ok := m.plat.(peerConfigPlatform); ok {
		if _, err := cfg.EnsureRelayPeer(m.dev, link.pubkey, endpoint, allowed); err != nil {
			return err
		}
	}
	return m.plat.SetPeer(m.dev, link.pubkey, endpoint, allowed)
}

func (m *peerManager) removeLocked(link *peerLink) {
	_ = m.plat.RemovePeer(m.dev, link.pubkey)
	if cfg, ok := m.plat.(peerConfigPlatform); ok {
		_ = cfg.RemoveRelayPeer(m.dev, link.pubkey)
	}
	link.present = false
	link.direct = false
	link.dialing = false
}

func fetchPeers(ctx context.Context, self string) ([]apiPeer, error) {
	u := "https://bypass.breadway.dev/api/peers"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if user, pass, ok := relayCredential(); ok {
		req.SetBasicAuth(user, pass)
	} else {
		// A bound device's public key identifies it when the device has no
		// relay credential, which older installs may not.
		q := req.URL.Query()
		q.Set("k", self)
		req.URL.RawQuery = q.Encode()
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer list: %s", resp.Status)
	}
	var out struct {
		Peers []apiPeer `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Peers, nil
}

// relayCredential reads the relay credential, preferring the state directory
// and falling back to the binary directory older Linux installs used.
func relayCredential() (string, string, bool) {
	for _, path := range []string{core.CredentialPath(), core.InstallDir() + "/socks-auth"} {
		if user, pass, ok := readAuthFile(path); ok && user != "" && pass != "" {
			return user, pass, true
		}
	}
	return "", "", false
}

func devicePubkey() string {
	data, err := os.ReadFile(core.DeviceIdentityPath())
	if err != nil {
		return ""
	}
	var id struct {
		Pubkey string `json:"pubkey"`
	}
	_ = json.Unmarshal(data, &id)
	return id.Pubkey
}

func handshakeAge(dev, pubkey string) (time.Duration, bool) {
	exe := "wg"
	if runtime.GOOS == "windows" {
		exe = `C:\Program Files\WireGuard\wg.exe`
	}
	out, err := exec.Command(exe, "show", dev, "latest-handshakes").Output()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != pubkey {
			continue
		}
		var unix int64
		if _, err := fmt.Sscanf(fields[1], "%d", &unix); err != nil || unix == 0 {
			return 0, false
		}
		return time.Since(time.Unix(unix, 0)), true
	}
	return 0, false
}
