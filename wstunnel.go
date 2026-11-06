package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const wstunnelVersion = "11.1.0"

// Pinned checksums for the platforms this tool downloads for. Add a line here
// when a new platform or version is supported; never fetch a checksum at
// runtime, because that would defeat the point of pinning.
var wstunnelSums = map[string]string{
	"linux/amd64":   "512edf4e7bb64fc133522220123514868fae75b5bae4124b53e396787276aa23",
	"windows/amd64": "b271d076fbba92fe3d8c9b7612bf17f4ac905d68614a6c40debd73107883d75e",
	"darwin/amd64":  "68bf470b58f6cb7d3dcd96deb42fb5676b8810ef7751a53f7d9e3f8178a1d085",
	"darwin/arm64":  "87fc0d68563248729c8c45359e5a7501041990145850c43c23a96e51656c2880",
}

func wstunnelExeName() string {
	if runtime.GOOS == "windows" {
		return "wstunnel.exe"
	}
	return "wstunnel"
}

func wstunnelAsset() string {
	return fmt.Sprintf("wstunnel_%s_%s_%s.tar.gz", wstunnelVersion, runtime.GOOS, runtime.GOARCH)
}

// findWstunnel looks next to the executable first so a bundled copy wins, then
// on PATH, then in the install directory.
func findWstunnel() (string, error) {
	name := wstunnelExeName()
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	candidate := filepath.Join(installDir(), name)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate, nil
	}
	return "", errors.New("wstunnel is not installed")
}

// downloadWstunnel fetches the pinned release, verifies its checksum, and
// extracts the executable into the install directory.
func downloadWstunnel() (string, error) {
	sum, ok := wstunnelSums[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("no pinned wstunnel checksum for %s/%s; install it manually", runtime.GOOS, runtime.GOARCH)
	}

	url := fmt.Sprintf("https://github.com/erebe/wstunnel/releases/download/v%s/%s", wstunnelVersion, wstunnelAsset())
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("download wstunnel: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download wstunnel: %s", resp.Status)
	}

	archive, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return "", err
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != sum {
		return "", errors.New("wstunnel checksum mismatch; refusing to install")
	}

	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return "", err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(header.Name) != wstunnelExeName() {
			continue
		}
		if err := os.MkdirAll(installDir(), 0700); err != nil {
			return "", err
		}
		dest := filepath.Join(installDir(), wstunnelExeName())
		file, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(file, io.LimitReader(tr, 256<<20)); err != nil {
			file.Close()
			os.Remove(dest)
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
		return dest, nil
	}
	return "", errors.New("wstunnel executable not found in the archive")
}

func ensureWstunnel() (string, error) {
	if path, err := findWstunnel(); err == nil {
		return path, nil
	}
	return downloadWstunnel()
}

// relayListening reports whether something already holds the relay port. Go
// does not set SO_REUSEADDR for UDP, so a second bind fails exactly when the
// port is taken.
func relayListening() bool {
	conn, err := net.ListenPacket("udp", net.JoinHostPort(relayHost, relayPort))
	if err != nil {
		return true
	}
	conn.Close()
	return false
}

// wstunnelProc supervises the wstunnel child process.
type wstunnelProc struct {
	path string
	log  *log.Logger

	mu    sync.Mutex
	cmd   *exec.Cmd
	alive bool
}

func newWstunnelProc(path string, logger *log.Logger) *wstunnelProc {
	return &wstunnelProc{path: path, log: logger}
}

// Ensure starts the client if it is not already running, and waits until the
// local relay accepts traffic.
func (w *wstunnelProc) Ensure(ctx context.Context) error {
	w.mu.Lock()
	if w.alive {
		w.mu.Unlock()
		return nil
	}
	// A leftover client from a previous run is fine to reuse: it speaks to the
	// same server and exposes the same relay.
	if w.cmd == nil && relayListening() {
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()

	if w.path == "" {
		return errors.New("wstunnel is not installed")
	}

	cmd := exec.Command(w.path, "client",
		"--http-upgrade-path-prefix", wstunnelPrefix,
		// Resolve the relay through the in-process DoH listener, not the
		// system resolver. On a filtered network the system resolver can
		// return a sinkhole, while the DoH bootstrap already knows the real
		// Aegis address. Verification stays on: Caddy serves a valid
		// certificate for dns.breadway.dev.
		"--dns-resolver", "dns://"+dohListenAddr,
		"--dns-resolver-prefer-ipv4",
		"--tls-verify-certificate",
		"-L", "udp://"+net.JoinHostPort(relayHost, relayPort)+":"+net.JoinHostPort(relayHost, aegisWGPort),
		"wss://"+dohHost,
	)
	cmd.Stdout = w.log.Writer()
	cmd.Stderr = w.log.Writer()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start wstunnel: %w", err)
	}

	w.mu.Lock()
	w.cmd = cmd
	w.alive = true
	w.mu.Unlock()

	go func(cmd *exec.Cmd) {
		err := cmd.Wait()
		w.mu.Lock()
		if w.cmd == cmd {
			w.cmd = nil
			w.alive = false
		}
		w.mu.Unlock()
		if err != nil {
			w.log.Printf("wstunnel exited: %v", err)
		}
	}(cmd)

	for i := 0; i < 40; i++ {
		if relayListening() {
			w.log.Printf("websocket fallback relay listening on %s", net.JoinHostPort(relayHost, relayPort))
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}

	_ = cmd.Process.Kill()
	return errors.New("wstunnel started but the relay never opened")
}

func (w *wstunnelProc) Stop() {
	w.mu.Lock()
	cmd := w.cmd
	w.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
