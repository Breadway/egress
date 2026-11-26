package egress

import (
	"context"
	"io"
	"log"
	"testing"

	"egress/internal/split"
)

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
