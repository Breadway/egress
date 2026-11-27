package egress

import (
	"context"
	"sync"
	"time"

	"egress/internal/netid"
	sysplatform "egress/internal/platform"
	"egress/internal/split"
)

// currentNetwork resolves the platform signals to a canonical network ID. The
// result is cached because the same interface and gateway answer the same
// identity, and the portal probe should not run on every supervisor tick.
func currentNetwork(iface, gateway string) (string, netid.Record) {
	networkMu.Lock()
	defer networkMu.Unlock()
	if iface == networkIface && gateway == networkGateway && networkID != "" {
		return networkID, networkRecord
	}
	rawSignals := sysplatform.ReadNetworkSignals(iface, gateway)
	raw := netid.Raw{
		SSID:         rawSignals.SSID,
		DNSSuffix:    rawSignals.DNSSuffix,
		GatewayMAC:   rawSignals.GatewayMAC,
		DHCPServer:   rawSignals.DHCPServer,
		Subnet:       rawSignals.Subnet,
		Captive:      rawSignals.Captive,
		DNSResolvers: rawSignals.DNSResolvers,
		GatewayIP:    rawSignals.GatewayIP,
	}
	// Aliases are the keys older clients used for this gateway. They exist to
	// find an existing profile and to ask the server to merge its shared feed;
	// they are not used as weak identity signals. Before this identity existed
	// the key always included the gateway, with "unknown" when the SSID could
	// not be read.
	var aliases []string
	legacySSIDKey := ""
	if gateway != "" {
		aliases = append(aliases, "unknown|"+gateway)
		if rawSignals.SSID != "" {
			legacySSIDKey = rawSignals.SSID + "|" + gateway
			aliases = append(aliases, legacySSIDKey)
		}
	}
	// A link with no strong anchor, or one whose strong signals cannot produce
	// an ID (an SSID with no gateway or separator yet), must not create a
	// stored identity. Keep the old key, which is at least stable per gateway.
	sig := netid.Build(raw)
	if !sig.StrongAnchor() || sig.CanonicalID() == "" {
		fallback := split.NetworkKey(rawSignals.SSID, gateway)
		networkIface, networkGateway = iface, gateway
		networkID, networkRecord = fallback, netid.Record{ID: fallback, Aliases: aliases}
		return fallback, networkRecord
	}
	store, err := netid.Open(split.ProfileDir())
	if err == nil {
		verifier := netid.ProbeVerify(probeNetwork(iface))
		rec, rerr := store.Resolve(raw, aliases, verifier)
		// A resolved identity is still usable when the store cannot be
		// written, as in the per-user proxy reading the system directory.
		if rec.ID != "" {
			networkIface, networkGateway = iface, gateway
			networkID, networkRecord = rec.ID, rec
			if gateway != "" {
				split.MigrateLegacyProfile(split.ProfileDir(), rec.ID, "unknown|"+gateway, legacySSIDKey)
			}
			if rerr == nil {
				_ = store.SetProbes(rec.ID, probeExpectations(rec.ID))
			}
			return rec.ID, rec
		}
	}
	// A read-only profile directory or a malformed store must not stop the
	// tunnel. The canonical ID is deterministic from the signals, so a
	// process that cannot persist the store (the per-user proxy) still uses
	// the same key as the daemon.
	fallback := sig.CanonicalID()
	if fallback == "" {
		fallback = split.NetworkKey(rawSignals.SSID, gateway)
	}
	networkIface, networkGateway = iface, gateway
	networkID = fallback
	networkRecord = netid.Record{ID: fallback, Aliases: aliases}
	return fallback, networkRecord
}

// probeNetwork checks a saved expectation over the direct path. Inconclusive
// answers are ignored by ProbeVerify.
func probeNetwork(iface string) func(string) (bool, bool) {
	return func(domain string) (bool, bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		res := split.ProbeDomain(ctx, domain, split.ProbeOptions{
			Interface: iface,
			Timeout:   3 * time.Second,
		})
		switch res.State {
		case split.StateBlocked:
			return true, true
		case split.StateAllowed:
			return false, true
		default:
			return false, false
		}
	}
}

// probeExpectations takes a few blocked domains from the saved profile so the
// next resolve can verify that a fuzzy match is really this network.
func probeExpectations(network string) []netid.Probe {
	profile, err := split.LoadProfile(split.ProfilePath(network), network)
	if err != nil {
		return nil
	}
	out := make([]netid.Probe, 0, 3)
	for domain, entry := range profile.Entries {
		if entry.State != split.StateBlocked || entry.Unserved {
			continue
		}
		out = append(out, netid.Probe{Domain: domain, Blocked: true})
		if len(out) == 3 {
			break
		}
	}
	return out
}

var (
	networkMu      sync.Mutex
	networkIface   string
	networkGateway string
	networkID      string
	networkRecord  netid.Record
)
