package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Signed update manifests. Releases are generic builds with no embedded device
// key; the manifest is signed offline with an Ed25519 key that never lives on
// the server. Clients embed only the public half.

const updateSchema = 1

// PublicKey is set at build time:
//
//	go build -ldflags "-X main.PublicKey=<base64>"
var PublicKey string

// Manifest is the signed description of one release. Signature covers the
// canonical JSON of every other field.
type Manifest struct {
	Schema    int    `json:"schema"`
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Released  string `json:"released"`
	Force     bool   `json:"force,omitempty"`
	Notes     string `json:"notes,omitempty"`
	Signature string `json:"signature,omitempty"`
}

func (m Manifest) payload() ([]byte, error) {
	copy := m
	copy.Signature = ""
	return json.Marshal(copy)
}

func Sign(m *Manifest, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("bad signing key length")
	}
	payload, err := m.payload()
	if err != nil {
		return err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return nil
}

// VerifyUpdateManifest checks the signature and every field a client depends
// on. goos and goarch are the running platform; a manifest for another target
// is rejected before any download.
func Verify(m *Manifest, pub ed25519.PublicKey, goos, goarch string) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("update public key is not configured")
	}
	if m.Schema != updateSchema {
		return fmt.Errorf("unsupported manifest schema %d", m.Schema)
	}
	if m.OS != goos || m.Arch != goarch {
		return fmt.Errorf("manifest is for %s/%s, this build is %s/%s", m.OS, m.Arch, goos, goarch)
	}
	if _, err := CompareVersions(m.Version, "0.0.0"); err != nil {
		return fmt.Errorf("bad version %q: %w", m.Version, err)
	}
	if len(m.SHA256) != 64 {
		return errors.New("bad sha256 length")
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return errors.New("bad sha256 encoding")
	}
	if m.Size <= 0 {
		return errors.New("bad size")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("bad signature encoding")
	}
	payload, err := m.payload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return errors.New("manifest signature does not verify")
	}
	return nil
}

// parseVersion parses 1 to 3 numeric components. v prefixes are accepted.
func ParseVersion(v string) ([3]int, error) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return out, errors.New("empty version")
	}
	parts := strings.Split(v, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return out, fmt.Errorf("version %q needs 1 to 3 numeric parts", v)
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return out, fmt.Errorf("version %q has a non-numeric part", v)
		}
		out[i] = n
	}
	return out, nil
}

// CompareVersions returns -1, 0 or 1 for a < b, a == b, a > b.
func CompareVersions(a, b string) (int, error) {
	av, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	bv, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		switch {
		case av[i] < bv[i]:
			return -1, nil
		case av[i] > bv[i]:
			return 1, nil
		}
	}
	return 0, nil
}

func PublicKeyBytes() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(PublicKey))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("this build has no update public key; rebuild with --update-key")
	}
	return ed25519.PublicKey(raw), nil
}

func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, errors.New("signing key is not base64")
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, fmt.Errorf("signing key is %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}
}
