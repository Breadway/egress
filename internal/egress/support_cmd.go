package egress

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"egress/internal/core"
	"egress/internal/health"
	"egress/internal/logx"
	"egress/internal/split"
)

// supportSecrets matches a credential on a line. Every value is replaced, not
// just the label, because the point of the archive is to be safe to send.
var supportSecrets = regexp.MustCompile(`(?i)(privatekey|presharedkey|password|passwd|token|secret)\s*[:=]\s*\S+`)

// supportKey matches a WireGuard style key on its own, which is what a config
// dump or a debug line looks like.
var supportKey = regexp.MustCompile(`\b[A-Za-z0-9+/]{43}=`)

func redactSupport(s string) string {
	s = supportSecrets.ReplaceAllString(s, "$1 = [redacted]")
	return supportKey.ReplaceAllString(s, "[redacted-key]")
}

// defaultSupportDir is the least surprising place for a file someone is about
// to attach to a message: the Desktop when there is one, else the home
// directory.
func defaultSupportDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "."
	}
	desktop := filepath.Join(home, "Desktop")
	if info, err := os.Stat(desktop); err == nil && info.IsDir() {
		return desktop
	}
	return home
}

// cmdSupport writes one archive with everything needed to explain a broken
// install, so a friend sends a single file instead of pasting four command
// outputs across messages.
func cmdSupport(args []string) error {
	fs := newFlagSet("support")
	debug := fs.Bool("debug", false, "trace commands")
	outDir := fs.String("out", "", "directory for the archive (default: Desktop)")
	upload := fs.Bool("upload", false, "also send the archive to the support endpoint")
	server := fs.String("server", defaultEnrollServer, "support service base URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))

	dir := *outDir
	if dir == "" {
		dir = defaultSupportDir()
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	path := filepath.Join(dir, "egress-support-"+time.Now().Format("20060102-150405")+".zip")

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	add := func(name string, data []byte) error {
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:     name,
			Method:   zip.Deflate,
			Modified: time.Now(),
		})
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}

	var summary strings.Builder
	fmt.Fprintf(&summary, "egress %s\n", reportVersion())
	fmt.Fprintf(&summary, "platform %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&summary, "install %s\n", core.InstallDir())
	if self, err := os.Executable(); err == nil {
		fmt.Fprintf(&summary, "running %s\n", self)
	}
	mode := "off"
	if split.Enabled() {
		mode = "on"
	}
	fmt.Fprintf(&summary, "split %s\n", mode)
	if id, err := loadDeviceIdentity(); err == nil && id.Pubkey != "" {
		fmt.Fprintf(&summary, "device %s %s\n", id.IP, id.Pubkey)
	}

	// The per-user proxy keeps its own learned profile, in the user's profile
	// rather than the install directory. A wrong "allowed" verdict shows up
	// there and nowhere else, and without it a bundle cannot explain why a
	// blocked site was dialled directly.
	type extraFile struct {
		name string
		data []byte
	}
	var extras []extraFile
	for _, dir := range []string{split.ProxyDir(), split.ProfileDir()} {
		matches, _ := filepath.Glob(filepath.Join(dir, "split-*.json"))
		for _, match := range matches {
			data, rerr := os.ReadFile(match)
			if rerr != nil {
				continue
			}
			name := "profile-" + filepath.Base(filepath.Dir(match)) + "-" + filepath.Base(match)
			extras = append(extras, extraFile{name, data})
		}
	}

	var diag bytes.Buffer
	if err := health.WriteDiagnose(&diag); err != nil {
		fmt.Fprintf(&diag, "diagnose failed: %v\n", err)
	}
	var logs bytes.Buffer
	logx.Tail(&logs, logPath(), 400)

	for name, data := range map[string][]byte{
		"summary.txt":  []byte(summary.String()),
		"diagnose.txt": []byte(diag.String()),
		"log.txt":      logs.Bytes(),
	} {
		if err := add(name, []byte(redactSupport(string(data)))); err != nil {
			return err
		}
	}
	for _, extra := range extras {
		if err := add(extra.name, []byte(redactSupport(string(extra.data)))); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", path)
	fmt.Println("attach that file when asking for help; keys and tokens are redacted")

	if !*upload {
		return nil
	}
	if err := uploadSupport(*server, path); err != nil {
		return err
	}
	return nil
}

// uploadSupport posts the bundle to the support endpoint. The device key says
// which enrolled device it came from; it is an identifier, not a secret, so the
// server treats the contents as untrusted input.
func uploadSupport(server, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	id, err := loadDeviceIdentity()
	if err != nil || id.Pubkey == "" {
		return fmt.Errorf("this device has no enrollment identity yet; run install first")
	}
	url := strings.TrimRight(server, "/") + "/api/support"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("X-Egress-Pubkey", id.Pubkey)
	req.Header.Set("X-Egress-Version", reportVersion())
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	fmt.Printf("uploaded to %.60s (%s)\n", url, strings.TrimSpace(string(body)))
	return nil
}
