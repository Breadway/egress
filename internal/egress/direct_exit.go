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

// exitTunnel is the data path to an exit. The TLS implementation dials a
// public listener; the DERP implementation uses the shared relay connection,
// which is the only option for an exit behind CGNAT.
type exitTunnel interface {
	Ensure(context.Context) error
	Stop()
	Connected() bool
	LocalAddr() string
}

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
	plat  peerSetter
	dev   string
	log   *log.Logger
	relay *derpTransport

	mu    sync.Mutex
	exits []split.DirectExit
	// peerExits are exits offered by devices in the circle. They are only
	// chosen when the person opted in, because using one sends traffic through
	// someone else's connection.
	peerExits  []split.DirectExit
	preferPeer bool
	prefixes   []string
	tunnel     exitTunnel
	pubkey     string
	kind       string
	relayKey   string
	active     bool
	lastErr    string

	wake chan struct{}
}

// directExitLocal is the loopback UDP port the exit relay exposes to the
// WireGuard service. 7108 belongs to the Aegis relay.
const directExitLocal = "127.0.0.1:7109"

func newDirectExit(plat peerSetter, dev string, relay *derpTransport, logger *log.Logger) *directExit {
	return &directExit{plat: plat, dev: dev, relay: relay, log: logger, wake: make(chan struct{}, 1)}
}

// SetExits records the exits published with the feed.
func (d *directExit) SetExits(list []split.DirectExit) {
	d.mu.Lock()
	d.exits = append([]split.DirectExit(nil), list...)
	d.mu.Unlock()
	d.nudge()
}

// ExitPubkey is the key of the peer currently carrying blocked destinations.
// A device that is both a circle peer and the active exit is one WireGuard
// peer, and the exit wins: the P2P manager must leave its routes alone.
func (d *directExit) ExitPubkey() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.active {
		return ""
	}
	return d.pubkey
}

// ActiveExit describes the peer currently carrying blocked traffic, when one
// is. The label comes from the published exit list so the GUI can name a
// person instead of a key.
func (d *directExit) ActiveExit() (label, kind, pubkey string, active bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.active {
		return "", "", "", false
	}
	label = ""
	for _, list := range [][]split.DirectExit{d.exits, d.peerExits} {
		for _, e := range list {
			if e.PubKey == d.pubkey {
				if e.Label != "" {
					label = e.Label
				}
				if e.Transport != "" {
					kind = e.Transport
				}
				return label, kind, d.pubkey, true
			}
		}
	}
	return label, d.kind, d.pubkey, true
}

// SetPeerExits records the circle's offered exits and whether they should win
// over the published ones.
func (d *directExit) SetPeerExits(list []split.DirectExit, prefer bool) {
	d.mu.Lock()
	d.peerExits = append([]split.DirectExit(nil), list...)
	d.preferPeer = prefer
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
	if d.preferPeer && len(d.peerExits) > 0 {
		return d.peerExits[0], true
	}
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
	kind := ex.Transport
	if kind == "" {
		kind = "tls"
	}
	host, port := "", ""
	if kind != "derp" {
		host, port = exitHostPort(ex.Endpoint)
		if host == "" {
			d.fallback()
			return
		}
	}
	d.mu.Lock()
	previous := ""
	if d.tunnel == nil || d.pubkey != ex.PubKey || d.kind != kind ||
		(kind == "derp" && d.relayKey != ex.RelayKey) {
		if d.pubkey != "" && d.pubkey != ex.PubKey {
			previous = d.pubkey
		}
		if d.tunnel != nil {
			d.tunnel.Stop()
		}
		if kind == "derp" {
			tunnel, terr := newDERPExitTunnel(ex.RelayKey, d.relay)
			if terr != nil {
				d.tunnel = nil
				d.pubkey = ex.PubKey
				d.kind = kind
				d.relayKey = ex.RelayKey
				d.mu.Unlock()
				d.noteError("exit relay: %v", terr)
				d.fallback()
				return
			}
			d.tunnel = tunnel
		} else {
			d.tunnel = wgtunnel.NewWithOptions(wgtunnel.Options{
				Local: directExitLocal,
				Host:  host,
				Port:  port,
				Path:  ex.Path,
			}, d.log)
		}
		d.pubkey = ex.PubKey
		d.kind = kind
		d.relayKey = ex.RelayKey
	}
	tunnel := d.tunnel
	d.mu.Unlock()
	if previous != "" {
		// Two exit peers claiming the same destinations is a coin toss in the
		// cryptokey routing; drop the one being replaced.
		_ = d.plat.RemovePeer(d.dev, previous)
		if cfg, ok := d.plat.(relayPeerConfigurer); ok {
			_ = cfg.RemoveRelayPeer(d.dev, previous)
		}
	}

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
	local := tunnel.LocalAddr()
	if local == "" {
		d.noteError("exit tunnel has no local address")
		d.fallback()
		return
	}
	if cfg, ok := d.plat.(relayPeerConfigurer); ok {
		restarted, err := cfg.EnsureRelayPeer(d.dev, ex.PubKey, local, allowed)
		if err != nil {
			d.noteError("exit config: %v", err)
			d.fallback()
			return
		}
		if restarted {
			d.log.Printf("split: tunnel restarted with the exit peer in its config")
		}
	}
	if err := d.plat.SetPeer(d.dev, ex.PubKey, local, allowed); err != nil {
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
