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

// derpTransport is one DERP connection per device, shared by everything that
// needs the relay: peer links, an exit this device consumes, and clients using
// this device as an exit. A second connection with the same node key would be
// a duplicate key, and the relay would shadow one of them, so there is exactly
// one client and a route table keyed by the remote relay key.
type derpTransport struct {
	log    *log.Logger
	priv   [32]byte
	public string
	region string
	// announceKey publishes this identity through /api/derp-key. Slot
	// identities are published through /api/exit/slot instead, so they must
	// not overwrite the device's own relay key.
	announceKey  bool
	reportHealth bool

	mu      sync.Mutex
	client  *derp.Client
	routes  map[[32]byte]*derpLink
	relays  []derp.Relay
	next    int
	lastErr string
}

// derpLink is one local UDP socket attached to a remote relay key. WireGuard
// writes to the socket (Attach), or the socket dials the WireGuard listener
// (AttachDial), and the link carries those datagrams over the shared relay.
type derpLink struct {
	transport *derpTransport
	remote    [32]byte
	conn      *net.UDPConn
	dialed    bool
	last      addrSlot
	once      sync.Once
}

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
	return newDERPTransportWithKey(logger, priv, true, true)
}

// newDERPTransportWithKey builds a connection with a chosen identity. Exit
// slots use this with announce and reporting off: their key is published to the
// assigned client, not as the device's relay key.
func newDERPTransportWithKey(logger *log.Logger, priv [32]byte, announce, report bool) (*derpTransport, error) {
	pub, err := derpPublicKey(priv)
	if err != nil {
		return nil, err
	}
	return &derpTransport{
		log: logger, priv: priv, public: pub,
		announceKey: announce, reportHealth: report,
		routes: map[[32]byte]*derpLink{},
	}, nil
}

// decodeKey parses a base64 32-byte key, which is how peer and relay keys
// travel in JSON.
func decodeKey(text string) ([32]byte, error) {
	var out [32]byte
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != 32 {
		return out, errors.New("not a 32-byte base64 key")
	}
	copy(out[:], raw)
	return out, nil
}

// PublicKey is the relay identity this device publishes.
func (t *derpTransport) PublicKey() string { return t.public }

// Attach returns a loopback socket that WireGuard should use as a peer
// endpoint. Datagrams read from it go to the remote relay key; datagrams from
// that key are written back to the last WireGuard source address.
func (t *derpTransport) Attach(remote [32]byte) (*derpLink, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("derp local socket: %w", err)
	}
	link := &derpLink{transport: t, remote: remote, conn: conn}
	if err := t.register(link); err != nil {
		conn.Close()
		return nil, err
	}
	go link.readLoop()
	return link, nil
}

// AttachDial returns a socket connected to target. Replies from target go to
// the remote relay key. It is the exit side: WireGuard listens on target, and
// the link speaks for one relayed client.
func (t *derpTransport) AttachDial(remote [32]byte, target string) (*derpLink, error) {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("derp exit socket: %w", err)
	}
	link := &derpLink{transport: t, remote: remote, conn: conn, dialed: true}
	if err := t.register(link); err != nil {
		conn.Close()
		return nil, err
	}
	go link.readLoop()
	return link, nil
}

func (t *derpTransport) register(link *derpLink) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.routes[link.remote]; ok && existing != link {
		return errors.New("that relay key is already attached")
	}
	t.routes[link.remote] = link
	return nil
}

func (t *derpTransport) unregister(link *derpLink) {
	t.mu.Lock()
	if t.routes[link.remote] == link {
		delete(t.routes, link.remote)
	}
	t.mu.Unlock()
}

// LocalAddr is the address to give WireGuard.
func (l *derpLink) LocalAddr() string { return l.conn.LocalAddr().String() }

// Close ends the link and removes its route.
func (l *derpLink) Close() {
	l.once.Do(func() {
		l.conn.Close()
		l.transport.unregister(l)
	})
}

func (l *derpLink) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !l.dialed {
			l.last.store(addr)
		}
		l.transport.send(l.remote, buf[:n])
	}
}

func (l *derpLink) deliver(pkt []byte) {
	if l.dialed {
		_, _ = l.conn.Write(pkt)
		return
	}
	addr := l.last.load()
	if addr == nil {
		return
	}
	_, _ = l.conn.WriteToUDP(pkt, addr)
}

func (t *derpTransport) send(remote [32]byte, pkt []byte) {
	client := t.currentClient()
	if client == nil {
		return
	}
	if err := client.Send(remote, pkt); err != nil {
		t.log.Printf("derp: send to %x: %v", remote[:4], err)
	}
}

func (t *derpTransport) currentClient() *derp.Client {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.client
}

// Run keeps the relay identity published and one DERP connection while at
// least one route needs it. Connection loss is retried with backoff, and the
// node list rotates so one unreachable relay does not disable everything.
func (t *derpTransport) Run(ctx context.Context) {
	if os.Getenv("EGRESS_DERP") == "off" {
		t.log.Printf("derp: disabled by EGRESS_DERP=off")
		return
	}
	t.loadRelays(ctx)
	announce := time.NewTicker(5 * time.Minute)
	defer announce.Stop()
	status := time.NewTicker(time.Minute)
	defer status.Stop()
	report := func() { t.reportStatus(ctx) }
	if t.reportHealth {
		report()
	}
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
	if t.announceKey {
		publish()
	}

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			t.closeClient()
			return
		}
		select {
		case <-announce.C:
			if t.announceKey {
				publish()
			}
		case <-status.C:
			if t.reportHealth {
				report()
			}
		default:
		}
		t.mu.Lock()
		need := len(t.routes) > 0
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
		case <-announce.C:
			if t.announceKey {
				publish()
			}
		case <-status.C:
			if t.reportHealth {
				report()
			}
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
	link := t.routes[src]
	t.mu.Unlock()
	if link != nil {
		link.deliver(pkt)
	}
}

// loadRelays builds the node list for the preferred region. If the public map
// cannot be read, the known Sydney nodes are used so a transient
// control-plane failure does not disable the fallback.
func (t *derpTransport) loadRelays(ctx context.Context) {
	region := strings.TrimSpace(os.Getenv("EGRESS_DERP_REGION"))
	if region == "" {
		region = derpDefaultRegion
	}
	relays, err := fetchDERPRelays(ctx, region)
	if err != nil || len(relays) == 0 {
		t.log.Printf("derp: map unavailable (%v); using Sydney defaults", err)
		relays = defaultDERPRelays()
	}
	t.mu.Lock()
	if len(t.relays) == 0 {
		t.relays = relays
		t.region = relays[0].Region
	}
	t.mu.Unlock()
}

func defaultDERPRelays() []derp.Relay {
	return []derp.Relay{
		{Host: "derp5e.tailscale.com", Port: "443", Region: "syd", Node: "5e"},
		{Host: "derp5f.tailscale.com", Port: "443", Region: "syd", Node: "5f"},
		{Host: "derp5g.tailscale.com", Port: "443", Region: "syd", Node: "5g"},
	}
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

// reportStatus sends the relay state to the server so the admin side can see
// why a device is not reachable through DERP without reading its log.
func (t *derpTransport) reportStatus(ctx context.Context) {
	connected, relay, lastErr := t.Status()
	t.mu.Lock()
	region := t.region
	routes := len(t.routes)
	t.mu.Unlock()
	body, err := json.Marshal(struct {
		Connected bool   `json:"connected"`
		Relay     string `json:"relay"`
		Region    string `json:"region"`
		Peers     int    `json:"peers"`
		LastError string `json:"last_error"`
		Version   string `json:"version"`
	}{
		Connected: connected, Relay: relay, Region: region,
		Peers: routes, LastError: lastErr, Version: core.BuildVersion,
	})
	if err != nil {
		return
	}
	if err := peerAPI(ctx, "POST", "/api/derp-status", body, nil); err != nil {
		t.log.Printf("derp: status report: %v", err)
	}
}
