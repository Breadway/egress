package egress

import (
	"context"
	"io"
	"log"
	"testing"

	"egress/internal/core"
	"egress/internal/split"
)

// fakeExitTunnel reports a live tunnel so reconcile reaches the peer split
// without a real DERP connection.
type fakeExitTunnel struct{ local string }

func (f *fakeExitTunnel) Ensure(context.Context) error { return nil }
func (f *fakeExitTunnel) Stop()                        {}
func (f *fakeExitTunnel) Connected() bool              { return true }
func (f *fakeExitTunnel) LocalAddr() string            { return f.local }

// Only prefixes Charon assigned to the exit go to the exit peer; the rest stay
// on the hub so Charon exits them.
func TestDirectExitSplitsAssignedPrefixes(t *testing.T) {
	plat := &fakePeerPlatform{}
	exitKey := b64Key(5)
	relayKey := b64Key(4)
	d := newDirectExit(plat, "wg0", newTestRelay(), log.New(io.Discard, "", 0))
	d.SetExits([]split.DirectExit{{
		ID: "hestia", Transport: "derp", RelayKey: relayKey, PubKey: exitKey,
	}})
	d.SetAssignFunc(func(prefixes []string) map[string][]string {
		out := map[string][]string{}
		for _, p := range prefixes {
			if p == "203.0.113.9" {
				out["hestia"] = append(out["hestia"], p)
			} else {
				out[""] = append(out[""], p)
			}
		}
		return out
	})
	// Pre-seed a live tunnel with the same identity so reconcile does not try
	// to attach a real relay.
	d.mu.Lock()
	d.tunnel = &fakeExitTunnel{local: "127.0.0.1:7109"}
	d.pubkey = exitKey
	d.kind = "derp"
	d.relayKey = relayKey
	d.mu.Unlock()
	d.SetPrefixes([]string{"203.0.113.9", "198.51.100.7"})

	d.reconcile(context.Background())

	var exitAllowed, hubAllowed []string
	for _, c := range plat.calls {
		if c.kind != "set" {
			continue
		}
		switch c.pubkey {
		case exitKey:
			exitAllowed = c.allowed
		case core.AegisPublicKey:
			hubAllowed = c.allowed
		}
	}
	if !containsPrefix(exitAllowed, "203.0.113.9/32") {
		t.Fatalf("exit allowed = %v, want the assigned prefix", exitAllowed)
	}
	if containsPrefix(exitAllowed, "198.51.100.7/32") {
		t.Fatalf("exit allowed = %v, must not carry the cloud prefix", exitAllowed)
	}
	if !containsPrefix(hubAllowed, "198.51.100.7/32") || !containsPrefix(hubAllowed, core.TunnelSubnet) {
		t.Fatalf("hub allowed = %v, want the cloud prefix and the subnet", hubAllowed)
	}
	if containsPrefix(hubAllowed, "203.0.113.9/32") {
		t.Fatalf("hub allowed = %v, must not claim the exit prefix", hubAllowed)
	}
}

func TestDirectExitPrefersPeerExitOnlyWhenAsked(t *testing.T) {
	d := &directExit{log: log.New(io.Discard, "", 0), wake: make(chan struct{}, 1)}
	d.SetExits([]split.DirectExit{{ID: "charon", Endpoint: "140.238.198.192:7443"}})
	d.SetPeerExits([]split.DirectExit{{ID: "friend", Endpoint: "192.168.122.1:7443"}}, false)
	if ex, ok := d.first(); !ok || ex.ID != "charon" {
		t.Fatalf("first = %+v, want the published exit", ex)
	}
	d.SetPeerExits([]split.DirectExit{{ID: "friend", Endpoint: "192.168.122.1:7443"}}, true)
	if ex, ok := d.first(); !ok || ex.ID != "friend" {
		t.Fatalf("first = %+v, want the peer exit", ex)
	}
	// Without an offered peer exit the published one still applies.
	d.SetPeerExits(nil, true)
	if ex, ok := d.first(); !ok || ex.ID != "charon" {
		t.Fatalf("first = %+v, want the published exit as fallback", ex)
	}
}

func TestDirectExitChoicePinsRegisteredExit(t *testing.T) {
	t.Setenv("EGRESS_STATE_DIR", t.TempDir())
	d := &directExit{log: log.New(io.Discard, "", 0), wake: make(chan struct{}, 1)}
	d.SetExits([]split.DirectExit{
		{ID: "hestia", Endpoint: "203.0.113.10:7443"},
		{ID: "charon", Endpoint: "203.0.113.11:7443"},
	})
	if ex, ok := d.first(); !ok || ex.ID != "hestia" {
		t.Fatalf("automatic first = %+v, want hestia", ex)
	}
	if err := d.SetChoice("charon"); err != nil {
		t.Fatal(err)
	}
	if ex, ok := d.first(); !ok || ex.ID != "charon" {
		t.Fatalf("preferred first = %+v, want charon", ex)
	}
	// A preferred exit that disappears falls back to the feed instead of
	// leaving the connection without an exit.
	if err := d.SetChoice("missing"); err != nil {
		t.Fatal(err)
	}
	if ex, ok := d.first(); !ok || ex.ID != "hestia" {
		t.Fatalf("missing preferred first = %+v, want hestia", ex)
	}
	if err := d.SetChoice(""); err != nil {
		t.Fatal(err)
	}
	if ex, ok := d.first(); !ok || ex.ID != "hestia" {
		t.Fatalf("automatic after clear first = %+v, want hestia", ex)
	}
}

func TestDirectExitChoiceCanForceCloudRelay(t *testing.T) {
	t.Setenv("EGRESS_STATE_DIR", t.TempDir())
	d := &directExit{log: log.New(io.Discard, "", 0), wake: make(chan struct{}, 1)}
	d.SetExits([]split.DirectExit{
		{ID: "hestia", Endpoint: "203.0.113.10:7443"},
		{ID: "charon", Endpoint: "203.0.113.11:7443"},
	})
	d.SetPeerExits([]split.DirectExit{{ID: "friend", Endpoint: "203.0.113.12:7443", PubKey: "friend-key"}}, true)

	if err := d.SetChoice("cloud"); err != nil {
		t.Fatal(err)
	}
	if ex, ok := d.first(); ok {
		t.Fatalf("cloud choice returned direct exit %+v", ex)
	}
	if got := d.Choice(); got != cloudExitChoice {
		t.Fatalf("choice = %q, want %q", got, cloudExitChoice)
	}

	// An explicit direct exit beats the peer preference.
	if err := d.SetChoice("charon"); err != nil {
		t.Fatal(err)
	}
	if ex, ok := d.first(); !ok || ex.ID != "charon" {
		t.Fatalf("charon choice = %+v, want charon", ex)
	}

	// Automatic keeps the peer preference.
	if err := d.SetChoice(""); err != nil {
		t.Fatal(err)
	}
	if ex, ok := d.first(); !ok || ex.ID != "friend" {
		t.Fatalf("automatic choice = %+v, want the peer exit", ex)
	}
}

func TestDerpExitTunnelAttaches(t *testing.T) {
	relay := newTestRelay()
	key := b64Key(3)
	tunnel, err := newDERPExitTunnel(key, relay)
	if err != nil {
		t.Fatalf("new tunnel: %v", err)
	}
	if err := tunnel.Ensure(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if tunnel.LocalAddr() == "" {
		t.Fatal("no local address")
	}
	raw, _ := decodeKey(key)
	if relay.routes[raw] == nil {
		t.Fatal("relay key is not attached")
	}
	if tunnel.Connected() {
		t.Fatal("tunnel should not claim a connection without a relay client")
	}
	tunnel.Stop()
	if relay.routes[raw] != nil {
		t.Fatal("stop did not detach the relay key")
	}
}

// A DERP exit has no endpoint by design; reconcile must not reject it as an
// empty address before it reaches the relay tunnel.
func TestDirectExitAcceptsDerpExitWithoutEndpoint(t *testing.T) {
	plat := &fakePeerPlatform{}
	relay := newTestRelay()
	d := newDirectExit(plat, "wg0", relay, log.New(io.Discard, "", 0))
	d.SetExits([]split.DirectExit{{
		ID: "hestia", Transport: "derp", RelayKey: b64Key(4), PubKey: b64Key(5),
	}})
	d.SetPrefixes([]string{"203.0.113.9"})
	d.reconcile(context.Background())
	tunnel, ok := d.tunnel.(*derpExitTunnel)
	if !ok {
		t.Fatalf("tunnel = %T, want the DERP exit tunnel", d.tunnel)
	}
	tunnel.Stop()
	if _, err := newDERPExitTunnel(b64Key(4), relay); err != nil {
		t.Fatalf("tunnel should be constructible: %v", err)
	}
}

func TestDirectExitRecreatesTunnelOnSlotKeyChange(t *testing.T) {
	plat := &fakePeerPlatform{}
	relay := newTestRelay()
	d := newDirectExit(plat, "wg0", relay, log.New(io.Discard, "", 0))
	firstKey := b64Key(4)
	secondKey := b64Key(6)
	mk := func(relayKey string) split.DirectExit {
		return split.DirectExit{ID: "hestia", Transport: "derp", RelayKey: relayKey, PubKey: b64Key(5)}
	}
	d.SetExits([]split.DirectExit{mk(firstKey)})
	d.SetPrefixes([]string{"203.0.113.9"})
	d.reconcile(context.Background())
	first := d.tunnel
	if first == nil {
		t.Fatal("no tunnel after the first exit")
	}
	rawFirst, _ := decodeKey(firstKey)
	if relay.routes[rawFirst] == nil {
		t.Fatal("first slot key is not attached")
	}

	d.SetExits([]split.DirectExit{mk(secondKey)})
	d.reconcile(context.Background())
	if d.tunnel == first {
		t.Fatal("tunnel was not recreated for the new slot key")
	}
	if relay.routes[rawFirst] != nil {
		t.Fatal("old slot key is still attached")
	}
	rawSecond, _ := decodeKey(secondKey)
	if relay.routes[rawSecond] == nil {
		t.Fatal("new slot key is not attached")
	}
	d.tunnel.Stop()
}
