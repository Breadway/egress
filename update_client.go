package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// defaultUpdateBase is reachable only through the tunnel. Aegis binds the
// update service to 10.88.0.1, so the public internet never sees it.
const defaultUpdateBase = "http://10.88.0.1:7107"

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
