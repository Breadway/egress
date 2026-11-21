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
