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
	"strings"
	"time"

	"egress/internal/update"
)

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
	if _, err := update.ParseVersion(*version); err != nil {
		return err
	}
	key, err := update.LoadSigningKey(*keyFile)
	if err != nil {
		return err
	}
	sum, size, err := hashFile(*binary)
	if err != nil {
		return err
	}
	m := update.Manifest{
		Schema:   1,
		Version:  strings.TrimPrefix(*version, "v"),
		OS:       *goos,
		Arch:     *goarch,
		SHA256:   sum,
		Size:     size,
		Released: time.Now().UTC().Format(time.RFC3339),
		Force:    *force,
		Notes:    *notes,
	}
	if err := update.Sign(&m, key); err != nil {
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
