package egress

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// derpExitTunnel is the client half of an exit reached over DERP. It carries
// the same WireGuard datagrams the TLS tunnel does, but over the shared relay
// connection instead of a public HTTPS listener, which is what makes an exit
// behind CGNAT usable.
type derpExitTunnel struct {
	transport *derpTransport
	relayKey  [32]byte

	mu   sync.Mutex
	link *derpLink
}

func newDERPExitTunnel(relayKey string, transport *derpTransport) (*derpExitTunnel, error) {
	if transport == nil {
		return nil, errors.New("no relay transport")
	}
	key, err := decodeKey(relayKey)
	if err != nil {
		return nil, fmt.Errorf("exit relay key: %w", err)
	}
	return &derpExitTunnel{transport: transport, relayKey: key}, nil
}

// Ensure attaches the loopback socket the WireGuard peer will point at. It is
// idempotent, matching the TLS tunnel's contract.
func (t *derpExitTunnel) Ensure(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.link != nil {
		return nil
	}
	link, err := t.transport.Attach(t.relayKey)
	if err != nil {
		return err
	}
	t.link = link
	return nil
}

func (t *derpExitTunnel) Stop() {
	t.mu.Lock()
	link := t.link
	t.link = nil
	t.mu.Unlock()
	if link != nil {
		link.Close()
	}
}

func (t *derpExitTunnel) Connected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.link == nil {
		return false
	}
	connected, _, _ := t.transport.Status()
	return connected
}

func (t *derpExitTunnel) LocalAddr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.link == nil {
		return ""
	}
	return t.link.LocalAddr()
}
