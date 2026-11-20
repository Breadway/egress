package egress

import (
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
