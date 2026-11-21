package egress

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

type peerCall struct {
	kind     string // set, remove
	endpoint string
	allowed  []string
	allowedN bool // allowed was not nil
}

type fakePeerPlatform struct {
	calls []peerCall
}

func (f *fakePeerPlatform) SetPeer(dev, pubkey, endpoint string, allowed []string) error {
	f.calls = append(f.calls, peerCall{kind: "set", endpoint: endpoint, allowed: allowed, allowedN: allowed != nil})
	return nil
}

func (f *fakePeerPlatform) RemovePeer(dev, pubkey string) error {
	f.calls = append(f.calls, peerCall{kind: "remove"})
	return nil
}

func (f *fakePeerPlatform) count(kind string) int {
	n := 0
	for _, c := range f.calls {
		if c.kind == kind {
			n++
		}
	}
	return n
}

func newTestManager(plat peerPlatform) *peerManager {
	return &peerManager{
		plat:      plat,
		dev:       "wg0",
		log:       log.New(io.Discard, "", 0),
		self:      "self",
		links:     map[string]*peerLink{},
		handshake: func(dev, pubkey string) (time.Duration, bool) { return 0, false },
		exclude:   func() string { return "" },
	}
}

func TestDialable(t *testing.T) {
	cases := map[string]bool{
		"":                   false,
		"127.0.0.1:55751":    false,
		"[::1]:55751":        false,
		"125.253.50.4:12603": true,
		"203.0.113.9:1":      true,
		"missing-port":       false,
		"host.example:1234":  true,
	}
	for endpoint, want := range cases {
		if got := dialable(endpoint); got != want {
			t.Errorf("dialable(%q) = %v, want %v", endpoint, got, want)
		}
	}
}

func TestPeerManagerSkipsSelfAndOffline(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.setDesired([]apiPeer{
		{PubKey: "self", IP: "10.88.0.2", Endpoint: "125.253.50.4:1000"},
		{PubKey: "relayed", IP: "10.88.0.21", Endpoint: "127.0.0.1:55751"},
		{PubKey: "offline", IP: "10.88.0.22"},
		{PubKey: "direct", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"},
	})
	if len(m.links) != 2 {
		t.Fatalf("links = %d, want the relayed and direct peers", len(m.links))
	}
	if m.links["relayed"].dialable {
		t.Fatal("a relayed peer must not be dialled")
	}
	if !m.links["direct"].dialable {
		t.Fatal("a public peer should be dialled")
	}
}

// A relayed peer is configured passively so it can dial us, and it must never
// be dialled at the loopback address the relay produces.
func TestPeerManagerConfiguresRelayedPeerPassively(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.setDesired([]apiPeer{{PubKey: "a", IP: "10.88.0.21", Endpoint: "127.0.0.1:55751"}})
	m.reconcile()
	m.reconcile()
	if len(plat.calls) != 1 {
		t.Fatalf("calls = %+v, want one passive configuration", plat.calls)
	}
	call := plat.calls[0]
	if call.kind != "set" || call.endpoint != "" || call.allowedN {
		t.Fatalf("passive peer = %+v, want no endpoint and untouched routes", call)
	}
	if !m.links["a"].present {
		t.Fatal("peer should be marked present")
	}
	if m.links["a"].dialing || m.links["a"].direct {
		t.Fatal("a relayed peer must not start a dial")
	}
}

func TestPeerManagerAddsOnePeerPerPass(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.setDesired([]apiPeer{
		{PubKey: "a", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"},
		{PubKey: "b", IP: "10.88.0.21", Endpoint: "203.0.113.10:51820"},
	})
	m.reconcile()
	if len(plat.calls) != 1 {
		t.Fatalf("calls = %d, want 1 (one configuration per pass)", len(plat.calls))
	}
	m.reconcile()
	if len(plat.calls) != 2 {
		t.Fatalf("calls = %d, want 2 after a second pass", len(plat.calls))
	}
}

func TestPeerManagerDialsAndPromotes(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.setDesired([]apiPeer{{PubKey: "a", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"}})
	// First pass creates the peer, second starts the dial.
	m.reconcile()
	m.reconcile()
	link := m.links["a"]
	if !link.dialing {
		t.Fatalf("peer should be dialing after two passes: %+v", link)
	}
	last := plat.calls[len(plat.calls)-1]
	if last.endpoint != "203.0.113.9:51820" || !last.allowedN || len(last.allowed) != 1 || last.allowed[0] != "10.88.0.20/32" {
		t.Fatalf("dial call = %+v", last)
	}
	// The handshake completes, but not until the window has passed.
	m.handshake = func(dev, pubkey string) (time.Duration, bool) { return 5 * time.Second, true }
	link.dialStart = time.Now().Add(-peerAttemptWindow - time.Second)
	m.reconcile()
	if !link.direct || link.dialing {
		t.Fatalf("peer should be direct: %+v", link)
	}
	if link.failures != 0 {
		t.Fatalf("failures = %d, want 0", link.failures)
	}
}

func TestPeerManagerFallsBackWhenHandshakeDoesNotCome(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.setDesired([]apiPeer{{PubKey: "a", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"}})
	m.reconcile()
	m.reconcile()
	link := m.links["a"]
	link.dialStart = time.Now().Add(-peerAttemptWindow - time.Second)
	m.reconcile()
	if link.direct || link.dialing {
		t.Fatalf("peer should be passive after a failed dial: %+v", link)
	}
	if len(plat.calls) == 0 {
		t.Fatal("no calls recorded")
	}
	last := plat.calls[len(plat.calls)-1]
	if last.endpoint != "" || !last.allowedN || len(last.allowed) != 0 {
		t.Fatalf("demotion call = %+v, want routes cleared", last)
	}
	if !link.present || !link.backoffUntil.After(time.Now()) {
		t.Fatalf("peer should stay present and backed off: %+v", link)
	}
	if m.links["a"].failures != 1 {
		t.Fatalf("failures = %d, want 1", m.links["a"].failures)
	}
}

func TestPeerManagerDemotesStaleDirectLink(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.handshake = func(dev, pubkey string) (time.Duration, bool) { return 5 * time.Second, true }
	m.setDesired([]apiPeer{{PubKey: "a", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"}})
	m.reconcile()
	m.reconcile()
	link := m.links["a"]
	link.dialStart = time.Now().Add(-peerAttemptWindow - time.Second)
	m.reconcile()
	if !link.direct {
		t.Fatal("peer should be direct")
	}
	m.handshake = func(dev, pubkey string) (time.Duration, bool) {
		return peerHandshakeStale + time.Minute, true
	}
	m.reconcile()
	if link.direct || !link.present {
		t.Fatalf("stale link should be demoted but kept: %+v", link)
	}
	last := plat.calls[len(plat.calls)-1]
	if last.endpoint != "" || !last.allowedN || len(last.allowed) != 0 {
		t.Fatalf("demotion call = %+v, want routes cleared", last)
	}
}

func TestPeerManagerRemovesPeerThatLeavesTheList(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.setDesired([]apiPeer{{PubKey: "a", IP: "10.88.0.21", Endpoint: "127.0.0.1:55751"}})
	m.reconcile()
	m.setDesired(nil)
	if len(m.links) != 0 {
		t.Fatalf("links = %+v, want empty", m.links)
	}
	if plat.count("remove") != 1 {
		t.Fatalf("remove calls = %d, want 1", plat.count("remove"))
	}
}

func TestPeerBackoffGrows(t *testing.T) {
	if peerBackoff(1) >= peerBackoff(2) || peerBackoff(2) >= peerBackoff(3) {
		t.Fatal("backoff should grow with repeated failures")
	}
}

func TestPeerManagerLeavesTheActiveExitAlone(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.exclude = func() string { return "a" }
	m.setDesired([]apiPeer{{PubKey: "a", IP: "10.88.0.2", Endpoint: "203.0.113.9:51820"}})
	m.reconcile()
	if len(plat.calls) != 0 {
		t.Fatalf("calls = %+v, want none while the exit owns the peer", plat.calls)
	}
	// The exit manager removes its own peer when it falls back; the P2P manager
	// must not remove the same identity as a peer leaving the list.
	m.links["a"].present = true
	m.setDesired(nil)
	if len(plat.calls) != 0 {
		t.Fatalf("calls = %+v, want no removal of an owned peer", plat.calls)
	}
}

func b64Key(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func newTestRelay() *derpTransport {
	return &derpTransport{
		log:    log.New(io.Discard, "", 0),
		peers:  map[[32]byte]*derpPeer{},
		byDerp: map[[32]byte]*derpPeer{},
	}
}

// A peer with no dialable address is exactly the case DERP exists for: it
// should reach the relay ahead of the star.
func TestPeerManagerRelayedPeerUsesDERP(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.relay = newTestRelay()
	key := b64Key(1)
	relayKey := b64Key(2)
	m.setDesired([]apiPeer{{PubKey: key, DerpPubKey: relayKey, IP: "10.88.0.20", Endpoint: "127.0.0.1:55751"}})
	m.reconcile()
	link := m.links[key]
	if !link.present || !link.derping {
		t.Fatalf("peer should be trying DERP: %+v", link)
	}
	last := plat.calls[len(plat.calls)-1]
	if last.endpoint == "" || !strings.HasPrefix(last.endpoint, "127.0.0.1:") {
		t.Fatalf("DERP endpoint = %q", last.endpoint)
	}
	if !last.allowedN || len(last.allowed) != 1 || last.allowed[0] != "10.88.0.20/32" {
		t.Fatalf("DERP routes = %+v", last.allowed)
	}
	// The relay address is the peer's relay key, not its WireGuard key.
	derpRaw, _ := decodeKey(relayKey)
	wgRaw, _ := decodeKey(key)
	if m.relay.byDerp[derpRaw] == nil {
		t.Fatal("relay key is not mapped to the peer socket")
	}
	if m.relay.byDerp[wgRaw] != nil {
		t.Fatal("WireGuard key must not be used as the relay address")
	}

	m.handshake = func(dev, pubkey string) (time.Duration, bool) { return 5 * time.Second, true }
	link.dialStart = time.Now().Add(-peerAttemptWindow - time.Second)
	m.reconcile()
	if !link.derped || link.derping {
		t.Fatalf("peer should be on DERP: %+v", link)
	}

	m.handshake = func(dev, pubkey string) (time.Duration, bool) {
		return peerHandshakeStale + time.Minute, true
	}
	m.reconcile()
	if link.derped || !link.present {
		t.Fatalf("stale DERP link should be demoted: %+v", link)
	}
	last = plat.calls[len(plat.calls)-1]
	if last.endpoint != "" || !last.allowedN || len(last.allowed) != 0 {
		t.Fatalf("demotion = %+v, want routes cleared", last)
	}
	// The registration stays so the pair can meet on the relay later.
	if m.relay.byDerp[derpRaw] == nil {
		t.Fatal("relay registration was dropped on demotion")
	}
}

// A direct attempt that does not answer moves to DERP, not straight to the
// star.
func TestPeerManagerDirectFailureFallsBackToDERP(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.relay = newTestRelay()
	key := b64Key(1)
	m.setDesired([]apiPeer{{PubKey: key, DerpPubKey: b64Key(2), IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"}})
	m.reconcile()
	m.reconcile()
	link := m.links[key]
	if !link.dialing {
		t.Fatalf("peer should be dialling directly first: %+v", link)
	}
	link.dialStart = time.Now().Add(-peerAttemptWindow - time.Second)
	m.reconcile()
	if !link.derping || link.dialing {
		t.Fatalf("peer should try DERP after a failed dial: %+v", link)
	}
	last := plat.calls[len(plat.calls)-1]
	if !strings.HasPrefix(last.endpoint, "127.0.0.1:") {
		t.Fatalf("DERP endpoint = %q", last.endpoint)
	}
}
