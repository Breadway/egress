package egress

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"

	"egress/internal/core"
)

// derpKeyPath holds the relay identity. It is separate from the WireGuard key
// on purpose: the relay learns this public key and uses it as a routing
// address, so it should not be the key that authenticates the tunnel.
func derpKeyPath() string {
	return filepath.Join(filepath.Dir(core.DeviceIdentityPath()), "derp.key")
}

// loadOrCreateDerpKey returns the device's relay private key, persisting a new
// one on first use. The scalar is clamped the way Curve25519 expects.
func loadOrCreateDerpKey() ([32]byte, string, error) {
	var priv [32]byte
	data, err := os.ReadFile(derpKeyPath())
	if err == nil {
		text := strings.TrimSpace(string(data))
		raw, derr := base64.StdEncoding.DecodeString(text)
		if derr == nil && len(raw) == 32 {
			copy(priv[:], raw)
			return priv, text, nil
		}
	}
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	text := base64.StdEncoding.EncodeToString(priv[:])
	if err := os.MkdirAll(filepath.Dir(derpKeyPath()), 0700); err != nil {
		return priv, "", err
	}
	if err := os.WriteFile(derpKeyPath(), []byte(text+"\n"), 0600); err != nil {
		return priv, "", err
	}
	return priv, text, nil
}

// announceDerpKey publishes the relay public key so peers can address this
// device through DERP. It is idempotent and safe to repeat.
func announceDerpKey(ctx context.Context, pub string) error {
	body, err := json.Marshal(struct {
		PubKey string `json:"pubkey"`
	}{PubKey: pub})
	if err != nil {
		return err
	}
	return peerAPI(ctx, "POST", "/api/derp-key", body, nil)
}

// derpPublicKey derives the public half of a relay private key.
func derpPublicKey(priv [32]byte) (string, error) {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}
