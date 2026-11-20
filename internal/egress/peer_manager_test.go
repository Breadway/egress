package egress

import (
	"io"
	"log"
	"testing"
	"time"
)

type fakePeerPlatform struct {
	set     []string
	removed []string
}

func (f *fakePeerPlatform) SetPeer(dev, pubkey, endpoint string, allowed []string) error {
	f.set = append(f.set, pubkey+" "+endpoint)
	return nil
}

func (f *fakePeerPlatform) RemovePeer(dev, pubkey string) error {
	f.removed = append(f.removed, pubkey)
	return nil
}

func newTestManager(plat peerPlatform) *peerManager {
	return &peerManager{
		plat:      plat,
		dev:       "wg0",
		log:       log.New(io.Discard, "", 0),
		self:      "self",
		links:     map[string]*peerLink{},
		handshake: func(dev, pubkey string) (time.Duration, bool) { return 0, false },
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

func TestPeerManagerSkipsSelfAndRelayed(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.setDesired([]apiPeer{
		{PubKey: "self", IP: "10.88.0.2", Endpoint: "125.253.50.4:1000"},
		{PubKey: "relayed", IP: "10.88.0.21", Endpoint: "127.0.0.1:55751"},
		{PubKey: "offline", IP: "10.88.0.22"},
		{PubKey: "direct", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"},
	})
	if len(m.links) != 1 {
		t.Fatalf("links = %d, want 1", len(m.links))
	}
	if _, ok := m.links["direct"]; !ok {
		t.Fatalf("direct peer missing: %+v", m.links)
	}
}

func TestPeerManagerAddsOneAttemptPerPass(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.setDesired([]apiPeer{
		{PubKey: "a", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"},
		{PubKey: "b", IP: "10.88.0.21", Endpoint: "203.0.113.10:51820"},
	})
	m.reconcile()
	if len(plat.set) != 1 {
		t.Fatalf("set calls = %d, want 1 (one attempt per pass)", len(plat.set))
	}
	m.reconcile()
	// The next pass starts the second peer rather than restarting the first.
	if len(plat.set) != 2 {
		t.Fatalf("set calls = %d, want 2 after a second pass", len(plat.set))
	}
	m.reconcile()
	// Both attempts are open, so nothing new is dialled.
	if len(plat.set) != 2 {
		t.Fatalf("set calls = %d, want 2 while both attempts are open", len(plat.set))
	}
}

func TestPeerManagerFallsBackWhenHandshakeDoesNotCome(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.setDesired([]apiPeer{{PubKey: "a", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"}})
	m.reconcile()
	link := m.links["a"]
	link.addedAt = time.Now().Add(-peerAttemptWindow - time.Second)
	m.reconcile()
	if len(plat.removed) != 1 || plat.removed[0] != "a" {
		t.Fatalf("removed = %v, want the failed peer", plat.removed)
	}
	if link.direct || !link.backoffUntil.After(time.Now()) {
		t.Fatalf("peer should be backed off after a failed attempt: %+v", link)
	}
}

func TestPeerManagerKeepsDirectLink(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.handshake = func(dev, pubkey string) (time.Duration, bool) { return 10 * time.Second, true }
	m.setDesired([]apiPeer{{PubKey: "a", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"}})
	m.reconcile()
	link := m.links["a"]
	link.addedAt = time.Now().Add(-peerAttemptWindow - time.Second)
	m.reconcile()
	if !link.direct {
		t.Fatal("peer should be direct once the handshake completes")
	}
	if len(plat.removed) != 0 {
		t.Fatalf("removed = %v, want none", plat.removed)
	}
	// A stale handshake drops the link and returns the pair to the star.
	m.handshake = func(dev, pubkey string) (time.Duration, bool) {
		return peerHandshakeStale + time.Minute, true
	}
	m.reconcile()
	if link.direct || len(plat.removed) != 1 {
		t.Fatalf("stale link should be removed: direct=%v removed=%v", link.direct, plat.removed)
	}
}

func TestPeerManagerDropsPeerThatLeavesTheList(t *testing.T) {
	plat := &fakePeerPlatform{}
	m := newTestManager(plat)
	m.handshake = func(dev, pubkey string) (time.Duration, bool) { return 5 * time.Second, true }
	m.setDesired([]apiPeer{{PubKey: "a", IP: "10.88.0.20", Endpoint: "203.0.113.9:51820"}})
	m.reconcile()
	m.setDesired(nil)
	if len(m.links) != 0 {
		t.Fatalf("links = %+v, want empty", m.links)
	}
	if len(plat.removed) != 1 {
		t.Fatalf("removed = %v, want the departed peer", plat.removed)
	}
}
