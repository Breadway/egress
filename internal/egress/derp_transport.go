package egress

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"egress/internal/core"
	"egress/internal/derp"
)

const (
	derpMapURL = "https://login.tailscale.com/derpmap/default"
	// derpDefaultRegion is where this user base lives. Both ends of a relayed
	// pair must be in the same DERP region; the region mesh forwards between
	// nodes in a region but not between regions.
	derpDefaultRegion = "syd"
)

// derpTransport keeps one DERP connection for this device and a loopback UDP
// socket per peer. WireGuard sends to that socket; the transport relays the
// datagrams to the peer's relay key, which is separate from its WireGuard key.
type derpTransport struct {
	log    *log.Logger
	priv   [32]byte
	public string
	region string

	mu      sync.Mutex
	client  *derp.Client
	peers   map[[32]byte]*derpPeer
	byDerp  map[[32]byte]*derpPeer
	relays  []derp.Relay
	next    int
	lastErr string
}

type derpPeer struct {
	wgText  string
	derpKey [32]byte
	conn    *net.UDPConn
	last    addrSlot
}

// addrSlot stores the source address WireGuard last sent from.
type addrSlot struct {
	mu  sync.Mutex
	udp *net.UDPAddr
}

func (a *addrSlot) store(addr *net.UDPAddr) {
	a.mu.Lock()
	a.udp = addr
	a.mu.Unlock()
}

func (a *addrSlot) load() *net.UDPAddr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.udp
}

// newDERPTransport loads this device's relay identity. The key is distinct
// from the WireGuard key: the relay sees it, so it must not be the key that
// authenticates the tunnel.
func newDERPTransport(logger *log.Logger) (*derpTransport, error) {
	priv, _, err := loadOrCreateDerpKey()
	if err != nil {
		return nil, err
	}
	pub, err := derpPublicKey(priv)
	if err != nil {
		return nil, err
	}
	return &derpTransport{
		log: logger, priv: priv, public: pub,
		peers: map[[32]byte]*derpPeer{}, byDerp: map[[32]byte]*derpPeer{},
	}, nil
}

// PublicKey is the relay identity this device publishes.
func (t *derpTransport) PublicKey() string { return t.public }

// Endpoint returns the loopback address WireGuard should use for this peer.
// wgPubkey identifies the WireGuard peer; derpPubkey is the relay address the
// datagrams are sent to.
func (t *derpTransport) Endpoint(wgPubkey, derpPubkey string) (string, error) {
	wgRaw, err := decodeKey(wgPubkey)
	if err != nil {
		return "", fmt.Errorf("peer key: %w", err)
	}
	derpRaw, err := decodeKey(derpPubkey)
	if err != nil {
		return "", fmt.Errorf("relay key: %w", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if peer, ok := t.peers[wgRaw]; ok {
		if peer.derpKey == derpRaw {
			return peer.conn.LocalAddr().String(), nil
		}
		// The peer re-announced a different relay key; stop routing the old
		// one before the new socket takes over.
		delete(t.byDerp, peer.derpKey)
		peer.derpKey = derpRaw
		t.byDerp[derpRaw] = peer
		return peer.conn.LocalAddr().String(), nil
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return "", fmt.Errorf("derp local socket: %w", err)
	}
	peer := &derpPeer{wgText: wgPubkey, derpKey: derpRaw, conn: conn}
	t.peers[wgRaw] = peer
	t.byDerp[derpRaw] = peer
	go t.readPeer(peer)
	return conn.LocalAddr().String(), nil
}

func decodeKey(text string) ([32]byte, error) {
	var out [32]byte
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != 32 {
		return out, errors.New("not a 32-byte base64 key")
	}
	copy(out[:], raw)
	return out, nil
}

// Release closes the peer's local socket.
func (t *derpTransport) Release(wgPubkey string) {
	raw, err := decodeKey(wgPubkey)
	if err != nil {
		return
	}
	t.mu.Lock()
	peer := t.peers[raw]
	delete(t.peers, raw)
	if peer != nil {
		delete(t.byDerp, peer.derpKey)
	}
	t.mu.Unlock()
	if peer != nil {
		peer.conn.Close()
	}
}

func (t *derpTransport) readPeer(peer *derpPeer) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := peer.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		peer.last.store(addr)
		client := t.currentClient()
		if client == nil {
			continue
		}
		if err := client.Send(peer.derpKey, buf[:n]); err != nil {
			t.log.Printf("derp: send to %x: %v", peer.derpKey[:4], err)
		}
	}
}

func (t *derpTransport) currentClient() *derp.Client {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.client
}

// Run keeps the relay identity published and a DERP connection while at least
// one peer is using it. Connection loss is retried with backoff, and the node
// list is rotated so one unreachable relay does not disable the fallback.
func (t *derpTransport) Run(ctx context.Context) {
	if os.Getenv("EGRESS_DERP") == "off" {
		t.log.Printf("derp: disabled by EGRESS_DERP=off")
		return
	}
	t.loadRelays(ctx)
	announce := time.NewTicker(5 * time.Minute)
	defer announce.Stop()
	var lastAnnounceErr string
	publish := func() {
		if err := announceDerpKey(ctx, t.public); err != nil {
			if err.Error() != lastAnnounceErr {
				t.log.Printf("derp: publish relay key: %v", err)
				lastAnnounceErr = err.Error()
			}
			return
		}
		if lastAnnounceErr != "" {
			t.log.Printf("derp: relay key published")
			lastAnnounceErr = ""
		}
	}
	publish()

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			t.closeClient()
			return
		}
		select {
		case <-announce.C:
			publish()
		default:
		}
		t.mu.Lock()
		need := len(t.peers) > 0
		client := t.client
		t.mu.Unlock()
		if !need {
			if client != nil {
				t.closeClient()
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
			continue
		}
		if client == nil {
			if err := t.connect(ctx); err != nil {
				t.mu.Lock()
				t.lastErr = err.Error()
				t.mu.Unlock()
				t.log.Printf("derp: %v", err)
				select {
				case <-ctx.Done():
				case <-time.After(backoff):
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			backoff = time.Second
			continue
		}
		select {
		case <-ctx.Done():
			t.closeClient()
			return
		case <-client.Done():
			t.log.Printf("derp: connection ended: %v", client.Err())
			t.closeClient()
		}
	}
}

func (t *derpTransport) closeClient() {
	t.mu.Lock()
	client := t.client
	t.client = nil
	t.mu.Unlock()
	if client != nil {
		client.Close()
	}
}

func (t *derpTransport) connect(ctx context.Context) error {
	t.mu.Lock()
	relays := append([]derp.Relay(nil), t.relays...)
	idx := t.next
	t.mu.Unlock()
	if len(relays) == 0 {
		t.loadRelays(ctx)
		t.mu.Lock()
		relays = append([]derp.Relay(nil), t.relays...)
		t.mu.Unlock()
		if len(relays) == 0 {
			return errors.New("no relay nodes")
		}
	}
	var lastErr error
	for i := 0; i < len(relays); i++ {
		relay := relays[(idx+i)%len(relays)]
		dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		client, err := derp.Dial(dialCtx, derp.Options{
			Relay:    relay,
			Private:  t.priv,
			Version:  core.BuildVersion,
			OnPacket: t.onPacket,
		})
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		t.mu.Lock()
		t.client = client
		t.region = relay.Region
		t.next = (idx + i + 1) % len(relays)
		t.lastErr = ""
		t.mu.Unlock()
		pub := client.PublicKey()
		t.log.Printf("derp: connected to %s (%s), relay key %x", relay.Host, relay.Region, pub[:4])
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no relay accepted the connection")
	}
	return lastErr
}

func (t *derpTransport) onPacket(src [32]byte, pkt []byte) {
	t.mu.Lock()
	peer := t.byDerp[src]
	t.mu.Unlock()
	if peer == nil {
		return
	}
	addr := peer.last.load()
	if addr == nil {
		return
	}
	if _, err := peer.conn.WriteToUDP(pkt, addr); err != nil {
		t.log.Printf("derp: deliver from %x: %v", src[:4], err)
	}
}

// loadRelays builds the node list for the preferred region. The public map is
// unauthenticated; if it cannot be read, the known Sydney nodes are used so a
// transient control-plane failure does not disable the fallback.
func (t *derpTransport) loadRelays(ctx context.Context) {
	region := strings.TrimSpace(os.Getenv("EGRESS_DERP_REGION"))
	if region == "" {
		region = derpDefaultRegion
	}
	relays, err := fetchDERPRelays(ctx, region)
	if err != nil || len(relays) == 0 {
		t.log.Printf("derp: map unavailable (%v); using Sydney defaults", err)
		relays = []derp.Relay{
			{Host: "derp5e.tailscale.com", Port: "443", Region: "syd", Node: "5e"},
			{Host: "derp5f.tailscale.com", Port: "443", Region: "syd", Node: "5f"},
			{Host: "derp5g.tailscale.com", Port: "443", Region: "syd", Node: "5g"},
		}
	}
	t.mu.Lock()
	if len(t.relays) == 0 {
		t.relays = relays
		t.region = relays[0].Region
	}
	t.mu.Unlock()
}

func fetchDERPRelays(ctx context.Context, want string) ([]derp.Relay, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, derpMapURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("derp map: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var m struct {
		Regions map[string]struct {
			RegionID   int    `json:"RegionID"`
			RegionCode string `json:"RegionCode"`
			RegionName string `json:"RegionName"`
			Nodes      []struct {
				Name     string `json:"Name"`
				HostName string `json:"HostName"`
				DERPPort int    `json:"DERPPort"`
			} `json:"Nodes"`
		} `json:"Regions"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	codes := make([]string, 0, len(m.Regions))
	for id := range m.Regions {
		codes = append(codes, id)
	}
	sort.Slice(codes, func(i, j int) bool {
		return m.Regions[codes[i]].RegionID < m.Regions[codes[j]].RegionID
	})
	pick := ""
	for id, region := range m.Regions {
		if strings.EqualFold(region.RegionCode, want) {
			pick = id
			break
		}
	}
	if pick == "" && len(codes) > 0 {
		pick = codes[0]
	}
	if pick == "" {
		return nil, errors.New("derp map has no regions")
	}
	region := m.Regions[pick]
	var relays []derp.Relay
	for _, node := range region.Nodes {
		if node.HostName == "" {
			continue
		}
		port := "443"
		if node.DERPPort > 0 {
			port = fmt.Sprint(node.DERPPort)
		}
		relays = append(relays, derp.Relay{
			Host: node.HostName, Port: port,
			Region: region.RegionCode, Node: node.Name,
		})
	}
	return relays, nil
}

// Status reports the connection state for the local status page.
func (t *derpTransport) Status() (connected bool, relay string, err string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		if last := t.client.LastRecv(); !last.IsZero() && time.Since(last) > 90*time.Second {
			return false, t.client.Relay().Host, "relay silent"
		}
		return true, t.client.Relay().Host, ""
	}
	return false, "", t.lastErr
}
