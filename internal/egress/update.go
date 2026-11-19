package egress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"egress/internal/core"
	"egress/internal/split"
	"egress/internal/update"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	force := fs.Bool("force", false, "retry a release that recently failed to apply")
	base := fs.String("base", defaultUpdateBase, "update service base URL")
	debug := fs.Bool("debug", false, "trace commands")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))
	if !*check && !*apply {
		*check = true
	}

	pub, err := update.PublicKeyBytes()
	if err != nil {
		return err
	}
	m, err := fetchUpdateManifest(context.Background(), *base, pub)
	if err != nil {
		return err
	}
	// The update check runs every minute. Its heartbeat is the only signal that
	// says "this machine is alive and polling", which a report cannot: reports
	// only happen on install, update or a manual command.
	sendHeartbeat(m.Version)
	current := buildVersion
	if current == "" {
		current = "0.0.0"
	}
	if applied, _ := appliedRelease(); applied == m.SHA256 {
		fmt.Printf("up to date: build %s, this release is already applied\n", current)
		return nil
	}
	cmp, err := update.CompareVersions(m.Version, current)
	if err != nil {
		return err
	}
	if err := checkManifestVersion(current, m); err != nil {
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
	// A release whose apply failed is not retried every minute: the timer
	// would otherwise loop on a broken build forever. A single failure is
	// usually transient, so the first retry is soon.
	if sha, at, count := failedRelease(); sha == m.SHA256 && !at.IsZero() && !*force {
		if wait := failedReleaseWait(count) - time.Since(at); wait > 0 {
			fmt.Printf("previous attempt for %s failed at %s; retrying in %s\n",
				m.Version, at.Format(time.RFC3339), wait.Round(time.Minute))
			return nil
		}
	}

	if err := newPlatform().RequirePrivilege(); err != nil {
		return err
	}
	staged, err := applyUpdate(*base, m, pub)
	if err != nil {
		if rerr := recordFailedRelease(m.SHA256); rerr != nil {
			debugf("could not record the failed release: %v", rerr)
		}
		return err
	}
	if staged {
		// update-apply records the release once the new binary is actually
		// installed and running. Recording it here claimed a release that the
		// scheduled task could still fail to apply.
		fmt.Printf("staged %s; the scheduled task applies it in a few seconds\n", m.Version)
		return nil
	}
	// Record the release so a forced republish of the same version applies
	// once instead of reinstalling on every poll.
	if err := recordAppliedRelease(m.SHA256); err != nil {
		debugf("could not record the applied release: %v", err)
	}
	fmt.Printf("updated to %s\n", m.Version)
	return nil
}

// checkManifestVersion refuses a signed but older release. Without this a
// replayed manifest can pin a device to a version with a known flaw; only an
// explicit forced republish may move backwards.
func checkManifestVersion(current string, m update.Manifest) error {
	cmp, err := update.CompareVersions(m.Version, current)
	if err != nil {
		return err
	}
	if cmp < 0 && !m.Force {
		return fmt.Errorf("refusing to downgrade from %s to %s (replayed or stale manifest)", current, m.Version)
	}
	return nil
}

// doAegisRequest builds a transport that dials the known Aegis address with
// the DoH host's SNI. It is the fallback when the system resolver cannot
// resolve the update host, which is exactly the case where the updater has to
// work anyway: the resolver it is failing on may be the one being replaced.
func doAegisRequest(req *http.Request, timeout time.Duration) (*http.Response, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, "tcp", net.JoinHostPort(core.AegisIPv4, "443"))
		},
		TLSClientConfig: &tls.Config{ServerName: core.DoHHost, MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	return client.Do(req)
}

// doUpdateRequest tries the normal path, then the Aegis fallback when the host
// is the default update host.
func doUpdateRequest(req *http.Request, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err == nil {
		return resp, nil
	}
	if !strings.HasPrefix(req.URL.String(), "https://"+core.DoHHost+"/") {
		return nil, err
	}
	debugf("update host did not resolve (%v); retrying against Aegis", err)
	fallback := req.Clone(req.Context())
	return doAegisRequest(fallback, timeout)
}

func fetchUpdateManifest(ctx context.Context, base string, pub ed25519.PublicKey) (update.Manifest, error) {
	var m update.Manifest
	url := strings.TrimRight(base, "/") + "/manifest?os=" + runtime.GOOS + "&arch=" + runtime.GOARCH
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return m, err
	}
	resp, err := doUpdateRequest(req, 15*time.Second)
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
	if err := update.Verify(&m, pub, runtime.GOOS, runtime.GOARCH); err != nil {
		return m, err
	}
	return m, nil
}

func applyUpdate(base string, m update.Manifest, pub ed25519.PublicKey) (bool, error) {
	if runtime.GOOS == "windows" {
		// The running executable is locked and the per-user tray holds it
		// too; a scheduled task applies the staged build after this process
		// exits. It records the result, because staging is not applying.
		if err := stageWindowsRelease(base, m); err != nil {
			return false, err
		}
		return true, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	tmpPath, err := downloadRelease(base, m)
	if err != nil {
		return false, err
	}
	defer os.Remove(tmpPath)

	// Keep a backup so a broken release can be rolled back without a second
	// network round trip.
	backup := exe + ".prev"
	if err := copyExecutable(exe, backup); err != nil {
		return false, fmt.Errorf("back up current binary: %w", err)
	}
	installArgs := []string{"install", "--keep-config"}
	if split.Enabled() {
		installArgs = append(installArgs, "--split")
	}
	cmd := exec.Command(tmpPath, installArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = copyExecutable(backup, exe)
		_ = newPlatform().StartService()
		return false, fmt.Errorf("install failed, previous binary restored: %w", err)
	}
	return false, nil
}

// downloadRelease fetches, verifies and returns a verified release binary in a
// temporary file. The caller removes it.
func downloadRelease(base string, m update.Manifest) (string, error) {
	tmp, err := os.CreateTemp("", "egress-update-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()

	url := strings.TrimRight(base, "/") + "/blob/" + m.SHA256
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}
	resp, err := doUpdateRequest(req, 5*time.Minute)
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("download: %s", resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, m.Size+1))
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	if n != m.Size {
		os.Remove(tmpPath)
		return "", fmt.Errorf("downloaded %d bytes, manifest says %d", n, m.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.SHA256 {
		os.Remove(tmpPath)
		return "", fmt.Errorf("sha256 mismatch: got %s want %s", got, m.SHA256)
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

// fileSHA256 hashes a file, used to decide whether a staged release is
// already on disk and intact.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
	// FailedSHA/FailedAt remember a release whose apply failed, so a broken
	// release is not retried every minute by the update timer.
	FailedSHA string `json:"failed_sha,omitempty"`
	FailedAt  string `json:"failed_at,omitempty"`
	// FailedCount separates a transient apply failure (a locked file, a
	// service that had not exited yet) from a release that keeps failing.
	FailedCount int `json:"failed_count,omitempty"`
}

// updateStateFile is a variable so tests can point it at a temporary file.
var updateStateFile = updateStatePath

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
	data, err := os.ReadFile(updateStateFile())
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return "", err
	}
	return st.ManifestSHA, nil
}

// failedRelease reports a release that failed to apply, when, and how many
// times in a row.
func failedRelease() (string, time.Time, int) {
	var st updateState
	data, err := os.ReadFile(updateStateFile())
	if err != nil || json.Unmarshal(data, &st) != nil {
		return "", time.Time{}, 0
	}
	at, _ := time.Parse(time.RFC3339, st.FailedAt)
	return st.FailedSHA, at, st.FailedCount
}

// failedReleaseWait is how long to wait before retrying a release that just
// failed. The first failure is usually transient (a locked image, a task that
// had not exited), so retry soon; a release that fails repeatedly waits.
func failedReleaseWait(count int) time.Duration {
	switch {
	case count <= 1:
		return 10 * time.Minute
	case count == 2:
		return 30 * time.Minute
	default:
		return 6 * time.Hour
	}
}

// recordFailedRelease remembers an apply failure so the timer backs off
// instead of retrying a broken release every minute.
func recordFailedRelease(sha string) error {
	st := updateState{FailedSHA: sha, FailedAt: time.Now().UTC().Format(time.RFC3339), FailedCount: 1}
	prevSHA, _, prevCount := failedRelease()
	if prevSHA == sha {
		st.FailedCount = prevCount + 1
	}
	if applied, err := appliedRelease(); err == nil {
		st.ManifestSHA = applied
	}
	path := updateStateFile()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func recordAppliedRelease(sha string) error {
	path := updateStateFile()
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

// sendHeartbeat tells the fleet that this device checked for an update. Best
// effort: a missed heartbeat must never fail the check.
func sendHeartbeat(latest string) {
	id, err := loadDeviceIdentity()
	if err != nil || id.Pubkey == "" {
		return
	}
	payload, err := json.Marshal(map[string]string{
		"pubkey":  id.Pubkey,
		"version": buildVersion,
		"latest":  latest,
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
	})
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost,
		strings.TrimRight(defaultEnrollServer, "/")+"/api/heartbeat", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
	_ = resp.Body.Close()
}
