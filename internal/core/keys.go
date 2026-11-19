package core

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// normalizeKey trims, validates and canonicalises a WireGuard private key.
func NormalizeKey(s string) (string, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	if s == "" {
		return "", errors.New("empty private key")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("private key is not valid base64: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes, got %d", len(raw))
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// GeneratePrivateKey creates a WireGuard private key on this machine. Used by
// first-activation enrollment so the private half never leaves the device.
func GeneratePrivateKey() (string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), nil
}

// PublicKey derives the Curve25519 public key. It uses crypto/ecdh so it works
// on Windows, which has no wg.exe, and so it never depends on wireguard-tools
// being installed yet.
func PublicKey(privateKey string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func RenderWGConfig(c TunnelConfig) string {
	var b strings.Builder
	b.WriteString("# managed by egress" + "\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s/32\n", c.ClientIP)
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	if runtime.GOOS == "linux" {
		// Table = off because these routes are added by hand. wg-quick does not
		// add an endpoint route in that mode, and the endpoint sits inside
		// 128.0.0.0/1, so without the pin the first handshake is routed into
		// the tunnel and never arrives.
		b.WriteString("Table = off\n")
		if c.Split {
			// Split mode: only the tunnel subnet is routed at bring-up.
			// Learned-blocked destinations get /32 routes from the supervisor,
			// so the default route stays on the physical link.
			b.WriteString("PostUp = ip route replace " + TunnelSubnet + " dev %i; " +
				"gw=$(ip route show default | awk '/default/ {print $3; exit}'); " +
				"dev=$(ip route show default | awk '/default/ {print $5; exit}'); " +
				"ip route replace " + AegisIPv4 + " via \"$gw\" dev \"$dev\"\n")
			b.WriteString("PostDown = ip route del " + TunnelSubnet + " dev %i || true; " +
				"ip route del " + AegisIPv4 + " || true\n")
		} else {
			b.WriteString("PostUp = ip route replace 0.0.0.0/1 dev %i; ip route replace 128.0.0.0/1 dev %i; " +
				"gw=$(ip route show default | awk '/default/ {print $3; exit}'); " +
				"dev=$(ip route show default | awk '/default/ {print $5; exit}'); " +
				"ip route replace " + AegisIPv4 + " via \"$gw\" dev \"$dev\"\n")
			b.WriteString("PostDown = ip route del 0.0.0.0/1 dev %i || true; ip route del 128.0.0.0/1 dev %i || true; " +
				"ip route del " + AegisIPv4 + " || true\n")
		}
	}
	// Windows and Darwin need no interface section extras: Windows swaps whole
	// tunnel services per endpoint, and wg-quick on Darwin adds the endpoint
	// host route itself before installing the AllowedIPs routes.
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", AegisPublicKey)
	allowed := c.AllowedIPs
	if allowed == "" {
		allowed = "0.0.0.0/0"
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}
