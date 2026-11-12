package health

import (
	"egress/internal/core"
	"egress/internal/platform"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestReadyMarkerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	if err := WriteReadyMarker(); err != nil {
		t.Fatal(err)
	}
	pid, age, err := readReadyMarker()
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() {
		t.Errorf("pid = %d, want %d", pid, os.Getpid())
	}
	if age < 0 || age > time.Minute {
		t.Errorf("age = %v, want a few seconds", age)
	}
	RemoveReadyMarker()
	if _, err := os.Stat(filepath.Join(dir, "egress-ready")); !os.IsNotExist(err) {
		t.Error("marker still on disk after removal")
	}
	if _, _, err := readReadyMarker(); err == nil {
		t.Error("reading a removed marker must fail")
	}
}

func TestReadyMarkerRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	for _, content := range []string{"", "not-a-pid\n", "0\n", "-4\n"} {
		if err := os.WriteFile(filepath.Join(dir, "egress-ready"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readReadyMarker(); err == nil {
			t.Errorf("content %q must not parse", content)
		}
	}
}

func TestPidAlive(t *testing.T) {
	if !pidAlive(os.Getpid()) {
		t.Error("own pid must be alive")
	}
	if runtime.GOOS == "windows" {
		t.Skip("FindProcess always succeeds on Windows; liveness is covered by ServiceActive there")
	}
	if pidAlive(1 << 30) {
		t.Error("absurd pid must not be alive")
	}
}

type readyFake struct {
	active bool
}

func (f readyFake) RequirePrivilege() error                  { return nil }
func (f readyFake) DefaultRoute() (string, string, error)    { return "", "", nil }
func (f readyFake) DefaultRoutes() ([]platform.Route, error) { return nil, nil }
func (f readyFake) InstallTools() error                      { return nil }
func (f readyFake) WriteTunnelConfig(core.TunnelConfig) (bool, error) {
	return false, nil
}
func (f readyFake) StartTunnel() error                    { return nil }
func (f readyFake) StopTunnel() error                     { return nil }
func (f readyFake) TunnelUp() bool                        { return false }
func (f readyFake) TunnelConfigured() bool                { return false }
func (f readyFake) EnsureEndpoint(string) error           { return nil }
func (f readyFake) RepinEndpoint(string, string) error    { return nil }
func (f readyFake) ApplyDNS(string, string) error         { return nil }
func (f readyFake) EnsureDNS(string, string) error        { return nil }
func (f readyFake) SecureInstallDir() error               { return nil }
func (f readyFake) InstallService(string, []string) error { return nil }
func (f readyFake) StartService() error                   { return nil }
func (f readyFake) StopService() error                    { return nil }
func (f readyFake) ServiceActive() bool                   { return f.active }
func (f readyFake) LivePublicKey() (string, error)        { return "", nil }
func (f readyFake) Enable() error                         { return nil }
func (f readyFake) Disable() error                        { return nil }
func (f readyFake) Remove() error                         { return nil }
func (f readyFake) Ping(string) bool                      { return true }
func (f readyFake) WstunnelPath() (string, error)         { return "", nil }
func (f readyFake) InstallWstunnel() (string, error)      { return "", nil }

// TestCheckSupervisorLive proves the gate that stops a foreign resolver on
// the DNS port from satisfying install or verify.
func TestCheckSupervisorLive(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	if err := CheckSupervisorLive(readyFake{active: false}, 0); err == nil {
		t.Error("inactive service must fail even with a good marker")
	}
	if err := WriteReadyMarker(); err != nil {
		t.Fatal(err)
	}
	if err := CheckSupervisorLive(readyFake{active: true}, ReadyMarkerMaxAge); err != nil {
		t.Errorf("fresh marker + active service must pass: %v", err)
	}
	if err := CheckSupervisorLive(readyFake{active: true}, 0); err != nil {
		t.Errorf("verify mode (no age limit) must pass: %v", err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "egress-ready"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := CheckSupervisorLive(readyFake{active: true}, ReadyMarkerMaxAge); err == nil {
		t.Error("hour-old marker must fail the install freshness check")
	}
	if err := CheckSupervisorLive(readyFake{active: true}, 0); err != nil {
		t.Errorf("verify mode must accept an old marker from a live process: %v", err)
	}
}
