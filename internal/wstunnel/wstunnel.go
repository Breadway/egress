package wstunnel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"egress/internal/core"
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
var Sums = map[string]string{
	"linux/amd64":   "512edf4e7bb64fc133522220123514868fae75b5bae4124b53e396787276aa23",
	"windows/amd64": "b271d076fbba92fe3d8c9b7612bf17f4ac905d68614a6c40debd73107883d75e",
	"darwin/amd64":  "68bf470b58f6cb7d3dcd96deb42fb5676b8810ef7751a53f7d9e3f8178a1d085",
	"darwin/arm64":  "87fc0d68563248729c8c45359e5a7501041990145850c43c23a96e51656c2880",
}

func ExeName() string {
	if runtime.GOOS == "windows" {
		return "wstunnel.exe"
	}
	return "wstunnel"
}

func assetName() string {
	return fmt.Sprintf("wstunnel_%s_%s_%s.tar.gz", wstunnelVersion, runtime.GOOS, runtime.GOARCH)
}

// Find looks next to the executable first so a bundled copy wins, then
// on PATH, then in the install directory.
func Find() (string, error) {
	name := ExeName()
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	candidate := filepath.Join(core.InstallDir(), name)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate, nil
	}
	return "", errors.New("wstunnel is not installed")
}

// Download fetches the pinned release, verifies its checksum, and
// extracts the executable into the install directory.
func Download() (string, error) {
	sum, ok := Sums[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("no pinned wstunnel checksum for %s/%s; install it manually", runtime.GOOS, runtime.GOARCH)
	}

	url := fmt.Sprintf("https://github.com/erebe/wstunnel/releases/download/v%s/%s", wstunnelVersion, assetName())
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
		if filepath.Base(header.Name) != ExeName() {
			continue
		}
		if err := os.MkdirAll(core.InstallDir(), 0700); err != nil {
			return "", err
		}
		dest := filepath.Join(core.InstallDir(), ExeName())
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

func Ensure() (string, error) {
	if path, err := Find(); err == nil {
		return path, nil
	}
	return Download()
}

// relayListening reports whether something already holds the relay port. Go
// does not set SO_REUSEADDR for UDP, so a second bind fails exactly when the
// port is taken.
func relayListening() bool {
	conn, err := net.ListenPacket("udp", net.JoinHostPort(core.RelayHost, core.RelayPort))
	if err != nil {
		return true
	}
	conn.Close()
	return false
}

// Proc supervises the wstunnel child process.
type Proc struct {
	path string
	log  *log.Logger

	mu    sync.Mutex
	cmd   *exec.Cmd
	alive bool
	// done is closed by the Wait goroutine when the current child exits.
	// Stop waits on it so the supervised state is settled by the time Stop
	// returns; otherwise a stale alive flag can make the next Ensure a
	// no-op while the relay port is already free.
	done chan struct{}
}

func NewProc(path string, logger *log.Logger) *Proc {
	return &Proc{path: path, log: logger}
}

// Ensure starts the client if it is not already running, and waits until the
// local relay accepts traffic.
func (w *Proc) Ensure(ctx context.Context) error {
	w.mu.Lock()
	alive := w.alive
	leftover := w.cmd == nil && relayListening()
	w.mu.Unlock()
	if alive {
		// The flag can outlive the child: Stop only kills, and the Wait
		// goroutine clears the fields a moment later. Verify the port is
		// actually held instead of trusting the flag, or the tunnel can be
		// pointed at a relay that no longer exists.
		for i := 0; i < 8; i++ {
			if relayListening() {
				return nil
			}
			w.mu.Lock()
			stillAlive := w.alive
			w.mu.Unlock()
			if !stillAlive {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
		if relayListening() {
			return nil
		}
		// Stale: the child is gone or never opened the port. Settle the
		// state before starting fresh so two clients never race.
		w.Stop()
	} else if leftover {
		// A leftover client from a previous run is fine to reuse: it speaks to the
		// same server and exposes the same relay.
		return nil
	}

	if w.path == "" {
		return errors.New("wstunnel is not installed")
	}

	cmd := exec.Command(w.path, "client",
		"--http-upgrade-path-prefix", core.WstunnelPrefix,
		// Resolve the relay through the in-process DoH listener, not the
		// system resolver. On a filtered network the system resolver can
		// return a sinkhole, while the DoH bootstrap already knows the real
		// Aegis address. Verification stays on: Caddy serves a valid
		// certificate for dns.breadway.dev.
		"--dns-resolver", "dns://"+core.DoHListenAddr,
		"--dns-resolver-prefer-ipv4",
		"--tls-verify-certificate",
		"-L", "udp://"+net.JoinHostPort(core.RelayHost, core.RelayPort)+":"+net.JoinHostPort(core.RelayHost, core.AegisWGPort),
		"wss://"+core.DoHHost,
	)
	cmd.Stdout = w.log.Writer()
	cmd.Stderr = w.log.Writer()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start wstunnel: %w", err)
	}

	w.mu.Lock()
	w.cmd = cmd
	w.alive = true
	done := make(chan struct{})
	w.done = done
	w.mu.Unlock()

	go func(cmd *exec.Cmd) {
		err := cmd.Wait()
		w.mu.Lock()
		if w.cmd == cmd {
			w.cmd = nil
			w.alive = false
		}
		if w.done == done {
			close(done)
		}
		w.mu.Unlock()
		if err != nil {
			w.log.Printf("wstunnel exited: %v", err)
		}
	}(cmd)

	for i := 0; i < 40; i++ {
		if relayListening() {
			w.log.Printf("websocket fallback relay listening on %s", net.JoinHostPort(core.RelayHost, core.RelayPort))
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

func (w *Proc) Stop() {
	w.mu.Lock()
	cmd := w.cmd
	done := w.done
	w.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	// Wait for the reaper so alive/cmd are settled on return. Without this,
	// trialUDP's Stop can leave a stale alive flag that makes the next
	// Ensure a no-op while the relay is already dead.
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

// Sum returns the pinned download checksum for a target.
func Sum(goos, goarch string) string {
	return Sums[goos+"/"+goarch]
}

// WstunnelIsOurs reports whether path holds a copy this tool could have
// installed: the embedded digest for this build, or the pinned download digest
// for this platform. Anything else is the user's own copy and remove leaves it.
func WstunnelIsOurs(path, embeddedSHA string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if embeddedSHA != "" && core.DigestMatches(data, embeddedSHA) {
		return true
	}
	if sum := Sum(runtime.GOOS, runtime.GOARCH); sum != "" && core.DigestMatches(data, sum) {
		return true
	}
	return false
}
