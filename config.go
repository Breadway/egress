package main

import (
	"bufio"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	dohURL        = "https://dns.breadway.dev/dns-query"
	dohHost       = "dns.breadway.dev"
	dohListenAddr = "127.0.0.1:7103"

	aegisIPv4      = "152.69.174.7"
	aegisWGPort    = "7105"
	aegisTunnelIP  = "10.88.0.1"
	aegisPublicKey = "MsU+DNi9YLMpLfsHifP2+nMLAiblNs0uvPsQs/U2ZUA="
	wgInterface    = "wg0"

	wstunnelPrefix  = "wg-tunnel"
	relayHost       = "127.0.0.1"
	relayPort       = "7108"
	defaultClientIP = "10.88.0.4"

	reportURL  = "https://bypass.breadway.dev/api/report"
	reportHost = "bypass.breadway.dev"

	probeInterval = 15 * time.Second
	trialInterval = 10 * time.Minute
	dnsCheckEvery = 60 * time.Second
)

// tunnelConfig is everything needed to write a WireGuard configuration.
type tunnelConfig struct {
	PrivateKey string
	ClientIP   string
	Endpoint   string
}

func (c tunnelConfig) DirectEndpoint() string { return aegisIPv4 + ":" + aegisWGPort }
func (c tunnelConfig) RelayEndpoint() string  { return relayHost + ":" + relayPort }

// normalizeKey trims, validates and canonicalises a WireGuard private key.
func normalizeKey(s string) (string, error) {
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

// publicKey derives the Curve25519 public key. It uses crypto/ecdh so it works
// on Windows, which has no wg.exe, and so it never depends on wireguard-tools
// being installed yet.
func publicKey(privateKey string) (string, error) {
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

func validIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func renderWGConfig(c tunnelConfig) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s/32\n", c.ClientIP)
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	if runtime.GOOS == "linux" {
		// Table = off because these routes are added by hand. wg-quick does not
		// add an endpoint route in that mode, and the endpoint sits inside
		// 128.0.0.0/1, so without the pin the first handshake is routed into
		// the tunnel and never arrives.
		b.WriteString("Table = off\n")
		b.WriteString("PostUp = ip route replace 0.0.0.0/1 dev %i; ip route replace 128.0.0.0/1 dev %i; " +
			"gw=$(ip route show default | awk '/default/ {print $3; exit}'); " +
			"dev=$(ip route show default | awk '/default/ {print $5; exit}'); " +
			"ip route replace " + aegisIPv4 + " via \"$gw\" dev \"$dev\"\n")
		b.WriteString("PostDown = ip route del 0.0.0.0/1 dev %i || true; ip route del 128.0.0.0/1 dev %i || true; " +
			"ip route del " + aegisIPv4 + " || true\n")
	}
	// Windows and Darwin need no interface section extras: Windows swaps whole
	// tunnel services per endpoint, and wg-quick on Darwin adds the endpoint
	// host route itself before installing the AllowedIPs routes.
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", aegisPublicKey)
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

// resolveKey prefers an explicit flag, then the key compiled in at build time,
// then a prompt.
func resolveKey(flagKey, flagFile string) (string, error) {
	if strings.TrimSpace(flagKey) != "" {
		return normalizeKey(flagKey)
	}
	if flagFile != "" {
		data, err := os.ReadFile(flagFile)
		if err != nil {
			return "", err
		}
		return normalizeKey(string(data))
	}
	if embeddedKey != "" {
		return normalizeKey(embeddedKey)
	}
	fmt.Fprint(os.Stderr, "WireGuard private key: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no key provided: %w", err)
	}
	return normalizeKey(line)
}

func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not start listening: %w", addr, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
