package egress

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Signed update manifests. Releases are generic builds with no embedded device
// key; the manifest is signed offline with an Ed25519 key that never lives on
// the server. Clients embed only the public half.

const updateSchema = 1

// updatePublicKey is set at build time:
//
//	go build -ldflags "-X main.updatePublicKey=<base64>"
var updatePublicKey string

// UpdateManifest is the signed description of one release. Signature covers the
// canonical JSON of every other field.
type UpdateManifest struct {
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

func (m UpdateManifest) payload() ([]byte, error) {
	copy := m
	copy.Signature = ""
	return json.Marshal(copy)
}

func SignUpdateManifest(m *UpdateManifest, key ed25519.PrivateKey) error {
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
func VerifyUpdateManifest(m *UpdateManifest, pub ed25519.PublicKey, goos, goarch string) error {
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
func parseVersion(v string) ([3]int, error) {
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
	av, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	bv, err := parseVersion(b)
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

func updatePublicKeyBytes() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(updatePublicKey))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("this build has no update public key; rebuild with --update-key")
	}
	return ed25519.PublicKey(raw), nil
}

func loadSigningKey(path string) (ed25519.PrivateKey, error) {
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

// cmdUpdateKeygen makes an Ed25519 keypair. The private half belongs on the
// machine that signs releases, not on the server.
func cmdUpdateKeygen(args []string) error {
	fs := newFlagSet("update-keygen")
	out := fs.String("out", "", "file to write the private key to")
	force := fs.Bool("force", false, "overwrite an existing key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := *out
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, ".keys", "egress-update-signing.key")
	}
	if !*force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; use --force to replace it", path)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0600); err != nil {
		return err
	}
	fmt.Printf("private key: %s\n", path)
	fmt.Printf("public key:  %s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

// cmdUpdateSign builds a signed manifest and stages the blob in the layout the
// update service serves.
func cmdUpdateSign(args []string) error {
	fs := newFlagSet("update-sign")
	keyFile := fs.String("key-file", "", "Ed25519 signing key")
	binary := fs.String("binary", "", "release binary to sign")
	goos := fs.String("os", "", "target GOOS")
	goarch := fs.String("arch", "", "target GOARCH")
	version := fs.String("version", "", "release version, for example 0.3.0")
	force := fs.Bool("force", false, "allow this release to replace a newer build")
	notes := fs.String("notes", "", "release notes shown by --check")
	outDir := fs.String("out", "", "output directory served by the update service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *binary == "" || *goos == "" || *goarch == "" || *version == "" || *outDir == "" {
		return errors.New("usage: egress update-sign --key-file K --binary B --os linux --arch amd64 --version V --out DIR")
	}
	if _, err := parseVersion(*version); err != nil {
		return err
	}
	key, err := loadSigningKey(*keyFile)
	if err != nil {
		return err
	}
	sum, size, err := hashFile(*binary)
	if err != nil {
		return err
	}
	m := UpdateManifest{
		Schema:   updateSchema,
		Version:  strings.TrimPrefix(*version, "v"),
		OS:       *goos,
		Arch:     *goarch,
		SHA256:   sum,
		Size:     size,
		Released: time.Now().UTC().Format(time.RFC3339),
		Force:    *force,
		Notes:    *notes,
	}
	if err := SignUpdateManifest(&m, key); err != nil {
		return err
	}
	blobDir := filepath.Join(*outDir, "blobs")
	manifestDir := filepath.Join(*outDir, "manifests")
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		return err
	}
	if err := copyFile(*binary, filepath.Join(blobDir, sum)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(manifestDir, *goos+"-"+*goarch+".json")
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0644); err != nil {
		return err
	}
	fmt.Printf("manifest: %s\nblob: %s\n", manifestPath, filepath.Join(blobDir, sum))
	return nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
