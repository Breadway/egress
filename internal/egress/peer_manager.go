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
	Label      string `json:"label"`
	PubKey     string `json:"pubkey"`
	IP         string `json:"ip"`
	Endpoint   string `json:"endpoint"`
	DerpPubKey string `json:"derp_pubkey"`
}

type peerLink struct {
	pubkey   string
	derpKey  string
	ip       string
	endpoint string
	dialable bool

	// present means the peer exists in WireGuard, with no routes by default.
	// A passive peer accepts an inbound handshake and learns the endpoint from
	// it, which is how a device behind the relay gets a direct link: the side
	// with a public address dials, and this side only has to be willing.
	present     bool
	dialing     bool
	dialStart   time.Time
	direct      bool
	derping     bool
	derped      bool
	derpPassive bool
	failures    int

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
	// peerDERPRetry is the retry cadence for a relayed link. The relay may be
	// up before the other side is, and a pair that just missed each other
	// should try again soon rather than wait out an exponential backoff.
	peerDERPRetry = 2 * time.Minute
)

// peerBackoff grows after repeated failures. A pair on a NAT that cannot punch
// should still retry after a router reboot, without being hammered meanwhile.
func peerBackoff(failures int) time.Duration {
	switch {
	case failures <= 1:
		return 30 * time.Second
	case failures == 2:
		return 2 * time.Minute
	default:
		return 5 * time.Minute
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
	// exclude names a peer another manager owns, currently the active exit.
	exclude func() string
	// relay carries peers that cannot be reached directly. Nil disables the
	// DERP fallback and leaves the Aegis star as the only alternative.
	relay *derpTransport

	mu        sync.Mutex
	links     map[string]*peerLink
	lastCount int
}

func newPeerManager(plat peerPlatform, dev string, logger *log.Logger, exclude func() string, relay *derpTransport) *peerManager {
	m := &peerManager{
		plat: plat, dev: dev, log: logger, links: map[string]*peerLink{},
		self: devicePubkey(), handshake: handshakeAge, exclude: exclude, relay: relay,
	}
	return m
}

// owned reports whether another manager controls this peer. The exit manager
// and the P2P manager address the same WireGuard identity, so the exit has to
// win while it is active or the two undo each other every tick.
func (m *peerManager) owned(pubkey string) bool {
	return m.exclude != nil && m.exclude() == pubkey
}

func (m *peerManager) Run(ctx context.Context) {
	if m.self == "" {
		m.log.Printf("peers: no device identity; direct links stay off")
		return
	}
	m.refresh(ctx)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	// A relay key or endpoint change should take a minute, not five. The list
	// is small and the request is authenticated.
	refresh := time.NewTicker(time.Minute)
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
			// Never remove a peer the exit manager owns: the peer is the same
			// identity, and it will clean up after itself.
			if link.present && !m.owned(key) {
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
		link.derpKey = p.DerpPubKey
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
		if m.owned(link.pubkey) {
			continue
		}
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
		}
		switch {
		case link.direct:
			if age, ok := m.handshake(m.dev, link.pubkey); !ok || age > peerHandshakeStale {
				m.log.Printf("peers: %s lost its direct link; trying DERP", link.ip)
				if m.startDERP(link, now) {
					continue
				}
				m.demote(link, now, "lost its direct link")
			}
		case link.dialing:
			if now.Sub(link.dialStart) < peerAttemptWindow {
				continue
			}
			if m.handshakeFresh(link) {
				link.dialing = false
				link.direct = true
				link.failures = 0
				if err := m.configure(link, link.endpoint, []string{link.ip + "/32"}); err != nil {
					m.log.Printf("peers: activate %s: %v", link.ip, err)
					link.direct = false
				} else {
					m.log.Printf("peers: direct link to %s (%s)", link.ip, link.endpoint)
				}
				continue
			}
			// A direct attempt that does not answer is exactly what DERP is
			// for; the star remains the last resort.
			if m.startDERP(link, now) {
				continue
			}
			m.demote(link, now, "did not answer directly")
		case link.derped:
			if age, ok := m.handshake(m.dev, link.pubkey); !ok || age > peerHandshakeStale {
				m.log.Printf("peers: %s lost its DERP link", link.ip)
				m.demote(link, now, "lost its DERP link")
			}
		case link.derpPassive:
			// The registration stays connected while idle, so the other side
			// can start a handshake at any time. Promote as soon as one lands.
			if m.handshakeFresh(link) {
				if endpoint, err := m.relay.Endpoint(link.pubkey, link.derpKey); err == nil {
					if err := m.configure(link, endpoint, []string{link.ip + "/32"}); err == nil {
						link.derpPassive = false
						link.derped = true
						link.failures = 0
						m.log.Printf("peers: DERP link to %s (%s)", link.ip, m.relayName())
						continue
					}
				}
			}
			if now.Before(link.backoffUntil) {
				continue
			}
			m.startDERP(link, now)
		case link.derping:
			if now.Sub(link.dialStart) < peerAttemptWindow {
				continue
			}
			if m.handshakeFresh(link) {
				link.derping = false
				link.derped = true
				link.failures = 0
				m.log.Printf("peers: DERP link to %s (%s)", link.ip, m.relayName())
				continue
			}
			m.demote(link, now, "DERP did not answer")
		default:
			if now.Before(link.backoffUntil) {
				continue
			}
			if link.dialable {
				if budget == 0 {
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
				continue
			}
			// A peer behind the relay has no dialable address of its own, so
			// DERP is the preferred path for it, ahead of the star.
			m.startDERP(link, now)
		}
	}
}

// handshakeFresh reports whether the peer's WireGuard session came up during
// the current attempt window rather than surviving from an earlier path.
func (m *peerManager) handshakeFresh(link *peerLink) bool {
	age, ok := m.handshake(m.dev, link.pubkey)
	return ok && age < 2*time.Minute
}

// startDERP moves the peer onto the relay. It returns false when DERP is not
// available or cannot be set up, so the caller can fall back to the star.
func (m *peerManager) startDERP(link *peerLink, now time.Time) bool {
	if m.relay == nil || link.derpKey == "" {
		return false
	}
	endpoint, err := m.relay.Endpoint(link.pubkey, link.derpKey)
	if err != nil {
		m.log.Printf("peers: derp endpoint for %s: %v", link.ip, err)
		return false
	}
	if err := m.configure(link, endpoint, []string{link.ip + "/32"}); err != nil {
		m.log.Printf("peers: derp %s: %v", link.ip, err)
		return false
	}
	link.dialing = false
	link.direct = false
	link.derping = true
	link.derpPassive = false
	link.dialStart = now
	m.log.Printf("peers: trying DERP for %s", link.ip)
	return true
}

// demote clears the peer's routes and returns it to the star, keeping the peer
// itself so the next attempt does not have to recreate it.
func (m *peerManager) demote(link *peerLink, now time.Time, reason string) {
	wasDERP := link.derping || link.derped
	if err := m.configure(link, "", []string{}); err != nil {
		m.log.Printf("peers: demote %s: %v", link.ip, err)
	}
	// A relayed pair only meets if both ends stay registered while they are
	// not actively handshaking. Keep the socket and the DERP connection for a
	// peer that was on the relay; the next attempt reuses them.
	if m.relay != nil && !wasDERP {
		m.relay.Release(link.pubkey)
	}
	link.dialing = false
	link.direct = false
	link.derping = false
	link.derped = false
	link.derpPassive = wasDERP
	link.failures++
	if wasDERP {
		link.backoffUntil = now.Add(peerDERPRetry)
	} else {
		link.backoffUntil = now.Add(peerBackoff(link.failures))
	}
	if reason != "" {
		m.log.Printf("peers: %s %s; back on Aegis", link.ip, reason)
	}
}

func (m *peerManager) relayName() string {
	if m.relay == nil {
		return "DERP"
	}
	_, relay, _ := m.relay.Status()
	if relay == "" {
		return "DERP"
	}
	return relay
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
	if m.relay != nil {
		m.relay.Release(link.pubkey)
	}
	link.present = false
	link.direct = false
	link.dialing = false
	link.derping = false
	link.derped = false
	link.derpPassive = false
}

func fetchPeers(ctx context.Context, self string) ([]apiPeer, error) {
	u := "https://bypass.breadway.dev/api/peers"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	applyPeerAuth(req, self)
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

// applyPeerAuth authenticates a peer API request. The relay credential is
// preferred; a bound device's public key identifies devices that do not hold
// one, which older installs may not.
func applyPeerAuth(req *http.Request, self string) {
	if user, pass, ok := relayCredential(); ok {
		req.SetBasicAuth(user, pass)
		return
	}
	q := req.URL.Query()
	q.Set("k", self)
	req.URL.RawQuery = q.Encode()
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
