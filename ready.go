package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// readyMarkerMaxAge bounds how old the install-time marker may be. Install
// just started the service, so a marker older than this cannot be ours: it
// is either a leftover or a foreign process squatting on the DNS port.
const readyMarkerMaxAge = 2 * time.Minute

func readyMarkerPath() string {
	// Shared with the installer through spoolDir, not TempDir: on Windows
	// TempDir is per-user while install runs elevated and the supervisor
	// runs as SYSTEM, so the two sides would never see the same marker
	// (the EGRESS-33 trap).
	return filepath.Join(spoolDir(), "egress-ready")
}

// writeReadyMarker records our PID once both DNS sockets are bound. Install
// and verify read it back to prove the process answering on 127.0.0.1:7103
// is the supervisor they started, not dnscrypt-proxy or a leftover.
func writeReadyMarker() error {
	return os.WriteFile(readyMarkerPath(), []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
}

// removeReadyMarker drops the marker on clean shutdown so a later verify
// cannot mistake a dead supervisor for a live one.
func removeReadyMarker() {
	_ = os.Remove(readyMarkerPath())
}

// readReadyMarker returns the recorded PID and the marker's age.
func readReadyMarker() (pid int, age time.Duration, err error) {
	data, err := os.ReadFile(readyMarkerPath())
	if err != nil {
		return 0, 0, err
	}
	pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, 0, fmt.Errorf("unreadable readiness marker")
	}
	info, err := os.Stat(readyMarkerPath())
	if err != nil {
		return 0, 0, err
	}
	return pid, time.Since(info.ModTime()), nil
}

// pidAlive reports whether pid exists. On Windows existence is all that is
// cheaply checkable; ServiceActive covers liveness there.
func pidAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// checkSupervisorLive verifies the service is active and the readiness
// marker points at a running process. maxAge <= 0 skips the freshness check
// (verify, which may run long after boot); install passes readyMarkerMaxAge
// so a stale leftover can never satisfy a fresh start.
func checkSupervisorLive(p platform, maxAge time.Duration) error {
	if !p.ServiceActive() {
		return errors.New("egress service is not active")
	}
	pid, age, err := readReadyMarker()
	if err != nil {
		return fmt.Errorf("no readiness marker from the supervisor: %w", err)
	}
	if maxAge > 0 && age > maxAge {
		return fmt.Errorf("readiness marker is %s old; the supervisor may be stale", age.Round(time.Second))
	}
	if !pidAlive(pid) {
		return fmt.Errorf("supervisor pid %d is not running", pid)
	}
	return nil
}
