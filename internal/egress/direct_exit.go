package egress

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"egress/internal/core"
	"egress/internal/split"
	"egress/internal/wgtunnel"
)

// peerSetter is the platform's peer control, kept as an interface so the
// manager stays testable and Linux, which needs none of this, simply does not
// implement it.
type peerSetter interface {
	SetPeer(dev, pubkey, endpoint string, allowed []string) error
	RemovePeer(dev, pubkey string) error
}

// relayPeerConfigurer is implemented by platforms whose tunnel service owns
// its peer list (Windows). The peer has to be in the config at service start,
// or inbound packets can be filtered even though the handshake works.
type relayPeerConfigurer interface {
	EnsureRelayPeer(dev, pubkey, endpoint string, allowed []string) (bool, error)
	RemoveRelayPeer(dev, pubkey string) error
}

// directExit carries learned-blocked destinations over the client's own tunnel
// to an exit, so that traffic never passes through Aegis. Aegis stays the
// fallback: when the exit is not connected, or nothing is routed yet, the same
// destinations go to the Aegis peer.
type directExit struct {
	plat peerSetter
	dev  string
	log  *log.Logger

	mu       sync.Mutex
	exits    []split.DirectExit
	prefixes []string
	tunnel   *wgtunnel.Tunnel
	pubkey   string
	active   bool
	lastErr  string

	wake chan struct{}
}

// directExitLocal is the loopback UDP port the exit relay exposes to the
// WireGuard service. 7108 belongs to the Aegis relay.
const directExitLocal = "127.0.0.1:7109"

func newDirectExit(plat peerSetter, dev string, logger *log.Logger) *directExit {
	return &directExit{plat: plat, dev: dev, log: logger, wake: make(chan struct{}, 1)}
}

// SetExits records the exits published with the feed.
func (d *directExit) SetExits(list []split.DirectExit) {
	d.mu.Lock()
	d.exits = append([]split.DirectExit(nil), list...)
	d.mu.Unlock()
	d.nudge()
}

// SetPrefixes records the destinations the split controller has routed. It is
// called under the route manager's lock, so it only stores and signals.
func (d *directExit) SetPrefixes(prefixes []string) {
	d.mu.Lock()
	d.prefixes = append([]string(nil), prefixes...)
	d.mu.Unlock()
	d.nudge()
}

func (d *directExit) nudge() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run reconciles the exit peer until the context ends.
func (d *directExit) Run(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			d.mu.Lock()
			tunnel := d.tunnel
			d.mu.Unlock()
			if tunnel != nil {
				tunnel.Stop()
			}
			return
		case <-d.wake:
		case <-tick.C:
		}
		d.reconcile(ctx)
	}
}

func (d *directExit) first() (split.DirectExit, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.exits) == 0 {
		return split.DirectExit{}, false
	}
	return d.exits[0], true
}

func (d *directExit) snapshot() ([]string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.prefixes...), d.active
}

func (d *directExit) reconcile(ctx context.Context) {
	ex, ok := d.first()
	if !ok {
		d.fallback()
		return
	}
	host, port := exitHostPort(ex.Endpoint)
	if host == "" {
		d.fallback()
		return
	}

	d.mu.Lock()
	if d.tunnel == nil || d.pubkey != ex.PubKey {
		if d.tunnel != nil {
			d.tunnel.Stop()
		}
		d.tunnel = wgtunnel.NewWithOptions(wgtunnel.Options{
			Local: directExitLocal,
			Host:  host,
			Port:  port,
			Path:  ex.Path,
		}, d.log)
		d.pubkey = ex.PubKey
	}
	tunnel := d.tunnel
	d.mu.Unlock()

	if err := tunnel.Ensure(ctx); err != nil {
		d.noteError("exit tunnel: %v", err)
		d.fallback()
		return
	}
	prefixes, _ := d.snapshot()
	if !tunnel.Connected() || len(prefixes) == 0 {
		d.fallback()
		return
	}

	allowed := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		allowed = append(allowed, p+"/32")
	}
	if cfg, ok := d.plat.(relayPeerConfigurer); ok {
		restarted, err := cfg.EnsureRelayPeer(d.dev, ex.PubKey, directExitLocal, allowed)
		if err != nil {
			d.noteError("exit config: %v", err)
			d.fallback()
			return
		}
		if restarted {
			d.log.Printf("split: tunnel restarted with the exit peer in its config")
		}
	}
	if err := d.plat.SetPeer(d.dev, ex.PubKey, directExitLocal, allowed); err != nil {
		d.noteError("exit peer: %v", err)
		d.fallback()
		return
	}
	// Aegis keeps only the tunnel subnet while the exit carries the routed
	// destinations, so the two peers never claim the same prefix.
	if err := d.plat.SetPeer(d.dev, core.AegisPublicKey, "", []string{core.TunnelSubnet}); err != nil {
		d.noteError("aegis peer: %v", err)
	}
	d.mu.Lock()
	was := d.active
	d.active = true
	d.mu.Unlock()
	if !was {
		d.log.Printf("split: blocked destinations leaving through %s (%s)", ex.ID, ex.Endpoint)
	}
}

// fallback puts every routed destination back on the Aegis peer and drops the
// exit peer. Running it when nothing changed is harmless: the commands are
// idempotent and cheap enough at this cadence.
func (d *directExit) fallback() {
	d.mu.Lock()
	pub := d.pubkey
	was := d.active
	prefixes := append([]string(nil), d.prefixes...)
	d.active = false
	d.mu.Unlock()

	if was && pub != "" {
		if err := d.plat.RemovePeer(d.dev, pub); err != nil {
			d.noteError("exit peer removal: %v", err)
		}
		if cfg, ok := d.plat.(relayPeerConfigurer); ok {
			_ = cfg.RemoveRelayPeer(d.dev, pub)
		}
		d.log.Printf("split: exit unavailable, blocked destinations back on Aegis")
	}
	allowed := append([]string{core.TunnelSubnet}, prefixSuffix(prefixes)...)
	if err := d.plat.SetPeer(d.dev, core.AegisPublicKey, "", allowed); err != nil {
		d.noteError("aegis peer: %v", err)
	}
}

func prefixSuffix(prefixes []string) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p+"/32")
	}
	return out
}

func (d *directExit) noteError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	d.mu.Lock()
	changed := msg != d.lastErr
	d.lastErr = msg
	d.mu.Unlock()
	if changed {
		d.log.Printf("split: %s", msg)
	}
}

func exitHostPort(endpoint string) (string, string) {
	host, port, err := net.SplitHostPort(endpoint)
	if err == nil {
		return host, port
	}
	return endpoint, "443"
}
