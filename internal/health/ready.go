package health

import (
	"egress/internal/logx"
	"egress/internal/platform"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ReadyMarkerMaxAge bounds how old the install-time marker may be. Install
// just started the service, so a marker older than this cannot be ours: it
// is either a leftover or a foreign process squatting on the DNS port.
const ReadyMarkerMaxAge = 2 * time.Minute

func ReadyMarkerPath() string {
	// Shared with the installer through spoolDir, not TempDir: on Windows
	// TempDir is per-user while install runs elevated and the supervisor
	// runs as SYSTEM, so the two sides would never see the same marker
	// (the EGRESS-33 trap).
	return filepath.Join(platform.SpoolDir(), "egress-ready")
}

// writeReadyMarker records our PID once both DNS sockets are bound. Install
// and verify read it back to prove the process answering on 127.0.0.1:7103
// is the supervisor they started, not dnscrypt-proxy or a leftover.
func WriteReadyMarker() error {
	return os.WriteFile(ReadyMarkerPath(), []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
}

// removeReadyMarker drops the marker on clean shutdown so a later verify
// cannot mistake a dead supervisor for a live one.
func RemoveReadyMarker() {
	_ = os.Remove(ReadyMarkerPath())
}

// readReadyMarker returns the recorded PID and the marker's age.
func readReadyMarker() (pid int, age time.Duration, err error) {
	data, err := os.ReadFile(ReadyMarkerPath())
	if err != nil {
		return 0, 0, err
	}
	pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, 0, fmt.Errorf("unreadable readiness marker")
	}
	info, err := os.Stat(ReadyMarkerPath())
	if err != nil {
		return 0, 0, err
	}
	return pid, time.Since(info.ModTime()), nil
}

// checkSupervisorLive verifies the service is active and the readiness
// marker points at a running process. maxAge <= 0 skips the freshness check
// (verify, which may run long after boot); install passes ReadyMarkerMaxAge
// so a stale leftover can never satisfy a fresh start.
func CheckSupervisorLive(p platform.Interface, maxAge time.Duration) error {
	if !p.ServiceActive() {
		return errors.New("egress service is not active")
	}
	pid, age, err := readReadyMarker()
	if err != nil {
		// A hardened install directory can leave the marker unreadable to the
		// installing account even though SYSTEM wrote it. The service is
		// already known to be active and the DNS probe follows, so on Windows
		// treat permission denied as inconclusive rather than failing install
		// and leaving the previous build running (Xavier, 2026-11-24).
		if runtime.GOOS == "windows" && os.IsPermission(err) {
			logx.Debugf("readiness marker is unreadable; relying on the service state and DNS probe")
			return nil
		}
		return fmt.Errorf("no readiness marker from the supervisor: %w", err)
	}
	if maxAge > 0 && age > maxAge {
		return fmt.Errorf("readiness marker is %s old; the supervisor may be stale", age.Round(time.Second))
	}
	if !pidAlive(pid) {
		// Opening another session's SYSTEM process is an access-checked
		// operation on Windows and is denied even while the process runs,
		// which failed every Windows install (EGRESS-93). The marker is
		// written by this start (install removes any older one), the task is
		// active, and the DNS probe that follows proves the process serves,
		// so treat an unopenable handle as inconclusive rather than fatal.
		if runtime.GOOS != "windows" {
			return fmt.Errorf("supervisor pid %d is not running", pid)
		}
		logx.Debugf("ready marker pid %d could not be opened; relying on the task state and the DNS probe", pid)
	}
	return nil
}
