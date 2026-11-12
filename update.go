package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// defaultUpdateBase goes through Caddy on the same hostname the network
// already allows. Split Windows clients have no WireGuard interface, so the
// old tunnel-only 10.88.0.1:7107 address would be unreachable for them.
const defaultUpdateBase = "https://dns.breadway.dev/updates"

// cmdUpdate checks for or applies a signed release. Applying runs the staged
// binary with install --keep-config, which preserves the existing tunnel key,
// address and split mode.
func cmdUpdate(args []string) error {
	fs := newFlagSet("update")
	check := fs.Bool("check", false, "report whether a newer release exists")
	apply := fs.Bool("apply", false, "download, verify and install a newer release")
	base := fs.String("base", defaultUpdateBase, "update service base URL")
	debug := fs.Bool("debug", false, "trace commands")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))
	if !*check && !*apply {
		*check = true
	}

	pub, err := updatePublicKeyBytes()
	if err != nil {
		return err
	}
	m, err := fetchUpdateManifest(context.Background(), *base, pub)
	if err != nil {
		return err
	}
	current := buildVersion
	if current == "" {
		current = "0.0.0"
	}
	if applied, _ := appliedRelease(); applied == m.SHA256 {
		fmt.Printf("up to date: build %s, this release is already applied\n", current)
		return nil
	}
	cmp, err := CompareVersions(m.Version, current)
	if err != nil {
		return err
	}
	if cmp <= 0 && !m.Force {
		fmt.Printf("up to date: build %s, latest %s\n", current, m.Version)
		return nil
	}
	fmt.Printf("update available: %s (current %s)\n", m.Version, current)
	if m.Notes != "" {
		fmt.Printf("notes: %s\n", m.Notes)
	}
	if !*apply {
		return nil
	}

	if err := newPlatform().RequirePrivilege(); err != nil {
		return err
	}
	if err := applyUpdate(*base, m, pub); err != nil {
		return err
	}
	// Record the release so a forced republish of the same version applies
	// once instead of reinstalling on every poll.
	if err := recordAppliedRelease(m.SHA256); err != nil {
		debugf("could not record the applied release: %v", err)
	}
	fmt.Printf("updated to %s\n", m.Version)
	return nil
}

func fetchUpdateManifest(ctx context.Context, base string, pub ed25519.PublicKey) (UpdateManifest, error) {
	var m UpdateManifest
	url := strings.TrimRight(base, "/") + "/manifest?os=" + runtime.GOOS + "&arch=" + runtime.GOARCH
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return m, err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return m, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return m, fmt.Errorf("manifest: %s", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&m); err != nil {
		return m, fmt.Errorf("decode manifest: %w", err)
	}
	if err := VerifyUpdateManifest(&m, pub, runtime.GOOS, runtime.GOARCH); err != nil {
		return m, err
	}
	return m, nil
}

func applyUpdate(base string, m UpdateManifest, pub ed25519.PublicKey) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "egress-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	url := strings.TrimRight(base, "/") + "/blob/" + m.SHA256
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: %s", resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, m.Size+1))
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if n != m.Size {
		return fmt.Errorf("downloaded %d bytes, manifest says %d", n, m.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.SHA256 {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, m.SHA256)
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		// The running executable is locked; a scheduled task applies it after
		// this process exits.
		return stageWindowsUpdate(m, tmpPath)
	}

	// Keep a backup so a broken release can be rolled back without a second
	// network round trip.
	backup := exe + ".prev"
	if err := copyExecutable(exe, backup); err != nil {
		return fmt.Errorf("back up current binary: %w", err)
	}
	installArgs := []string{"install", "--keep-config"}
	if splitEnabled() {
		installArgs = append(installArgs, "--split")
	}
	cmd := exec.Command(tmpPath, installArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = copyExecutable(backup, exe)
		_ = newPlatform().StartService()
		return fmt.Errorf("install failed, previous binary restored: %w", err)
	}
	return nil
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
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
	if err := os.Chmod(tmp, 0755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// parseWGConfigFile pulls the private key and client address out of an
// existing WireGuard config. Used by install --keep-config so an update can
// reuse the device identity instead of prompting for it.
func parseWGConfigFile(path string) (key, ip string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(name) {
		case "PrivateKey":
			key = strings.TrimSpace(value)
		case "Address":
			addr := strings.TrimSpace(value)
			if i := strings.Index(addr, ","); i >= 0 {
				addr = addr[:i]
			}
			if i := strings.Index(addr, "/"); i >= 0 {
				addr = addr[:i]
			}
			ip = strings.TrimSpace(addr)
		}
	}
	if key == "" {
		return "", "", errors.New("no PrivateKey in " + path)
	}
	if ip == "" {
		return "", "", errors.New("no Address in " + path)
	}
	return key, ip, nil
}

// existingTunnelConfig finds the installed config on this platform.
func existingTunnelConfig() (string, string, error) {
	var path string
	switch runtime.GOOS {
	case "linux":
		path = "/etc/wireguard/wg0.conf"
	case "windows":
		path = `C:\ProgramData\egress\wg0.conf`
	default:
		return "", "", fmt.Errorf("--keep-config is not supported on %s yet", runtime.GOOS)
	}
	return parseWGConfigFile(path)
}

// updateState records which signed release this install has applied. Without
// it, a republished build with the same version and a force flag would be
// reinstalled on every check.
type updateState struct {
	ManifestSHA string `json:"manifest_sha"`
}

func updateStatePath() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\ProgramData\egress\update-state.json`
	case "linux":
		return "/var/lib/egress/update-state.json"
	default:
		if dir, err := os.UserConfigDir(); err == nil {
			return filepath.Join(dir, "egress", "update-state.json")
		}
		return "update-state.json"
	}
}

func appliedRelease() (string, error) {
	var st updateState
	data, err := os.ReadFile(updateStatePath())
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return "", err
	}
	return st.ManifestSHA, nil
}

func recordAppliedRelease(sha string) error {
	path := updateStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(updateState{ManifestSHA: sha})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
