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
	"path/filepath"
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
	pubkey       string
	ip           string
	endpoint     string
	addedAt      time.Time
	direct       bool
	backoffUntil time.Time
}

const (
	// peerAttemptWindow is how long a direct attempt may take before the peer
	// is dropped and traffic returns to the star. A WireGuard handshake is
	// sub-second on a working path; ten seconds covers slow mobile links.
	peerAttemptWindow = 10 * time.Second
	// peerBackoff keeps a pair that cannot punch from retrying constantly. A
	// NAT mapping changes when a router reboots, so it is not permanent.
	peerBackoff = 30 * time.Minute
	// peerHandshakeStale is when a live link is considered gone. Persistent
	// keepalive rekeys about every two minutes.
	peerHandshakeStale = 4 * time.Minute
)

// peerManager turns the peer list into direct WireGuard links. It never
// removes the star: the Aegis peer carries 10.88.0.0/24, so a peer that is not
// added, or has just been removed, is reached through Aegis automatically.
type peerManager struct {
	plat peerPlatform
	dev  string
	log  *log.Logger
	self string

	// handshake is a variable so tests can drive the state machine without a
	// live WireGuard interface.
	handshake func(dev, pubkey string) (time.Duration, bool)

	mu    sync.Mutex
	links map[string]*peerLink
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

// shutdown drops every direct link so the process never leaves a peer behind
// that the next start would have to reconcile.
func (m *peerManager) shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, link := range m.links {
		if !link.addedAt.IsZero() {
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
}

// setDesired is the part of refresh that does not touch the network, split out
// so the state machine can be tested.
func (m *peerManager) setDesired(peers []apiPeer) {
	desired := map[string]apiPeer{}
	for _, p := range peers {
		if p.PubKey == "" || p.PubKey == m.self || p.IP == "" || !dialable(p.Endpoint) {
			continue
		}
		desired[p.PubKey] = p
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, link := range m.links {
		if _, ok := desired[key]; !ok {
			if !link.addedAt.IsZero() {
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
		if link.endpoint != p.Endpoint && link.endpoint != "" && link.addedAt.IsZero() {
			// A changed mapping needs a fresh attempt rather than the old
			// backoff, which was earned against an address that is gone.
			link.backoffUntil = time.Time{}
		}
		link.ip, link.endpoint = p.IP, p.Endpoint
	}
}

// dialable rejects addresses that cannot be reached from another machine: an
// empty endpoint, or the loopback the relay produces when a device reaches
// Aegis through the WebSocket tunnel.
func dialable(endpoint string) bool {
	if endpoint == "" {
		return false
	}
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
	// Only one new attempt per pass: on Windows each new peer restarts the
	// tunnel service, and several at once would restart it repeatedly.
	attempted := false
	for _, link := range m.links {
		switch {
		case link.direct:
			if age, ok := m.handshake(m.dev, link.pubkey); !ok || age > peerHandshakeStale {
				m.removeLocked(link)
				link.backoffUntil = now.Add(peerBackoff)
				m.log.Printf("peers: %s lost its direct link; back on Aegis", link.ip)
			}
		case !link.addedAt.IsZero():
			if now.Sub(link.addedAt) < peerAttemptWindow {
				continue
			}
			if age, ok := m.handshake(m.dev, link.pubkey); ok && age < 2*time.Minute {
				link.direct = true
				m.log.Printf("peers: direct link to %s (%s)", link.ip, link.endpoint)
				continue
			}
			m.removeLocked(link)
			link.backoffUntil = now.Add(peerBackoff)
			m.log.Printf("peers: %s did not answer directly; back on Aegis", link.ip)
		default:
			if attempted || now.Before(link.backoffUntil) {
				continue
			}
			allowed := []string{link.ip + "/32"}
			var err error
			if cfg, ok := m.plat.(peerConfigPlatform); ok {
				_, err = cfg.EnsureRelayPeer(m.dev, link.pubkey, link.endpoint, allowed)
			} else {
				err = m.plat.SetPeer(m.dev, link.pubkey, link.endpoint, allowed)
			}
			if err != nil {
				m.log.Printf("peers: %s: %v", link.ip, err)
				link.backoffUntil = now.Add(peerBackoff)
				continue
			}
			link.addedAt = now
			attempted = true
			m.log.Printf("peers: trying a direct link to %s (%s)", link.ip, link.endpoint)
		}
	}
}

func (m *peerManager) removeLocked(link *peerLink) {
	_ = m.plat.RemovePeer(m.dev, link.pubkey)
	if cfg, ok := m.plat.(peerConfigPlatform); ok {
		_ = cfg.RemoveRelayPeer(m.dev, link.pubkey)
	}
	link.addedAt = time.Time{}
	link.direct = false
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
	for _, path := range []string{core.CredentialPath(), filepath.Join(core.InstallDir(), "socks-auth")} {
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
