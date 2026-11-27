// Package netid resolves the current network to a stable canonical identity.
//
// The gateway address is not an identity: DHCP can move it on the same network.
// Each observable signal is hashed on its own, the hashes are scored against
// saved records, and a match is verified against the live signals before it is
// used. This keeps one profile and one shared feed across gateway changes.
package netid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"time"
)

// Signal kinds, strongest first.
const (
	KindSSID         = "ssid"
	KindDNSSuffix    = "dns_suffix"
	KindGatewayMAC   = "gateway_mac"
	KindCaptive      = "captive_portal"
	KindDHCPServer   = "dhcp_server"
	KindSubnet       = "subnet"
	KindDNSResolvers = "dns_resolvers"
	KindGatewayIP    = "gateway_ip"
)

// Raw is what the platform can observe about the current network. It never
// leaves the device; only the hashes in Signals do.
type Raw struct {
	SSID         string
	DNSSuffix    string
	GatewayMAC   string
	DHCPServer   string
	Subnet       string
	Captive      string
	DNSResolvers []string
	GatewayIP    string
}

// Signals is the hashed form of Raw. The values are deliberately not kept.
type Signals struct {
	Hashes map[string]string
}

var weights = map[string]float64{
	KindSSID:         4,
	KindDNSSuffix:    3,
	KindGatewayMAC:   3,
	KindCaptive:      2,
	KindDHCPServer:   1,
	KindSubnet:       1,
	KindDNSResolvers: 1,
	KindGatewayIP:    0.5,
}

func strongAnchor(kind string) bool {
	return kind == KindSSID || kind == KindDNSSuffix || kind == KindGatewayMAC
}

// Normalize canonicalizes a raw signal before hashing. Normalization is
// deterministic and shared across devices so the same network hashes the same.
func Normalize(kind, value string) string {
	v := strings.TrimSpace(value)
	switch kind {
	case KindSSID:
		return v
	case KindDNSSuffix:
		return strings.TrimSuffix(strings.ToLower(v), ".")
	case KindGatewayMAC, KindDHCPServer, KindGatewayIP:
		v = strings.ToLower(v)
		v = strings.ReplaceAll(v, ":", "")
		v = strings.ReplaceAll(v, "-", "")
		if kind == KindGatewayMAC || kind == KindDHCPServer || kind == KindGatewayIP {
			if ip := net.ParseIP(value); ip != nil {
				return ip.String()
			}
		}
		return v
	case KindSubnet:
		if ip, network, err := net.ParseCIDR(v); err == nil {
			return (&net.IPNet{IP: ip.Mask(network.Mask), Mask: network.Mask}).String()
		}
		return v
	case KindDNSResolvers:
		parts := splitResolvers(v)
		return strings.Join(parts, ",")
	default:
		return v
	}
}

func splitResolvers(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(strings.ToLower(f))
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Hash is the deterministic, domain-separated hash for one signal. It is
// comparable across devices by design; low-entropy values are obfuscated, not
// secret.
func Hash(kind, value string) string {
	v := Normalize(kind, value)
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("egress-net-v1:" + kind + ":" + v))
	return hex.EncodeToString(sum[:])[:32]
}

// Build turns Raw into the hashed signal set.
func Build(raw Raw) Signals {
	values := map[string]string{
		KindSSID:       raw.SSID,
		KindDNSSuffix:  raw.DNSSuffix,
		KindGatewayMAC: raw.GatewayMAC,
		KindCaptive:    raw.Captive,
		KindDHCPServer: raw.DHCPServer,
		KindSubnet:     raw.Subnet,
		KindGatewayIP:  raw.GatewayIP,
	}
	if len(raw.DNSResolvers) > 0 {
		values[KindDNSResolvers] = strings.Join(raw.DNSResolvers, ",")
	}
	s := Signals{Hashes: map[string]string{}}
	for kind, value := range values {
		if h := Hash(kind, value); h != "" {
			s.Hashes[kind] = h
		}
	}
	return s
}

// Fingerprint is the exact-match key over every available signal.
func (s Signals) Fingerprint() string {
	keys := make([]string, 0, len(s.Hashes))
	for kind := range s.Hashes {
		keys = append(keys, kind)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("egress-net-fingerprint-v1:")
	for _, kind := range keys {
		b.WriteString(kind)
		b.WriteByte(':')
		b.WriteString(s.Hashes[kind])
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])[:32]
}

// CanonicalID derives the preferred identity from the strong anchors. A Wi-Fi
// network with an SSID and a gateway MAC gets an ID that is stable across DHCP
// changes and distinct from the same SSID at another site. The DNS suffix is
// the fallback separator when the MAC cannot be read, so a platform that does
// not expose a lease suffix still agrees with one that does. With neither
// separator, the gateway address keeps two devices on the same link sharing a
// feed; it changes with DHCP, and the local store keeps the original ID
// through an alias when that happens. Wired networks use the MAC, then the
// suffix, then the gateway. Empty when nothing usable exists; the caller then
// creates a random ID.
func (s Signals) CanonicalID() string {
	ssid := s.Hashes[KindSSID]
	suffix := s.Hashes[KindDNSSuffix]
	mac := s.Hashes[KindGatewayMAC]
	gateway := s.Hashes[KindGatewayIP]
	if ssid != "" {
		switch {
		case mac != "":
			return hashID("wifi-mac:" + ssid + ":" + mac)
		case suffix != "":
			return hashID("wifi-dns:" + ssid + ":" + suffix)
		case gateway != "":
			// SSID alone cannot separate sites, so do not invent a stable ID.
			// The gateway is the old separator and is shared by the devices on
			// this link.
			return hashID("wifi-weak:" + ssid + ":" + gateway)
		default:
			return ""
		}
	}
	switch {
	case mac != "":
		return hashID("wired-mac:" + mac)
	case suffix != "":
		return hashID("wired-dns:" + suffix)
	default:
		return ""
	}
}

func hashID(seed string) string {
	sum := sha256.Sum256([]byte("egress-net-id-v1:" + seed))
	return hex.EncodeToString(sum[:])[:32]
}

// NewID returns a random canonical ID for a network with no strong anchor.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hashID("fallback:" + time.Now().UTC().Format(time.RFC3339Nano))
	}
	return hex.EncodeToString(b[:])
}

// Score returns the weighted overlap between two signal sets.
func (s Signals) Score(other map[string]string) float64 {
	var score float64
	for kind, h := range s.Hashes {
		if other[kind] != "" && other[kind] == h {
			score += weights[kind]
		}
	}
	return score
}

// StrongAnchor reports whether at least one strong signal is present.
func (s Signals) StrongAnchor() bool {
	for kind := range s.Hashes {
		if strongAnchor(kind) {
			return true
		}
	}
	return false
}
