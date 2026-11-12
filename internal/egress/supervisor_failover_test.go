package egress

import (
	"errors"
	"log"
	"os"
	"testing"
)

type rotateFake struct {
	routes []Route
	repins [][2]string
	err    error
}

func (f *rotateFake) RequirePrivilege() error               { return nil }
func (f *rotateFake) DefaultRoute() (string, string, error) { return "", "", errors.New("none") }
func (f *rotateFake) DefaultRoutes() ([]Route, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.routes, nil
}
func (f *rotateFake) InstallTools() error                          { return nil }
func (f *rotateFake) WriteTunnelConfig(tunnelConfig) (bool, error) { return false, nil }
func (f *rotateFake) StartTunnel() error                           { return nil }
func (f *rotateFake) StopTunnel() error                            { return nil }
func (f *rotateFake) TunnelUp() bool                               { return false }
func (f *rotateFake) TunnelConfigured() bool                       { return false }
func (f *rotateFake) EnsureEndpoint(string) error                  { return nil }
func (f *rotateFake) RepinEndpoint(gw, iface string) error {
	f.repins = append(f.repins, [2]string{gw, iface})
	return nil
}
func (f *rotateFake) ApplyDNS(string, string) error  { return nil }
func (f *rotateFake) EnsureDNS(string, string) error { return nil }

// SecureInstallDir is a no-op here to satisfy the platform interface; route
// rotation never touches the install directory.
func (f *rotateFake) SecureInstallDir() error               { return nil }
func (f *rotateFake) InstallService(string, []string) error { return nil }
func (f *rotateFake) StartService() error                   { return nil }
func (f *rotateFake) StopService() error                    { return nil }
func (f *rotateFake) ServiceActive() bool                   { return true }
func (f *rotateFake) LivePublicKey() (string, error)        { return "", nil }
func (f *rotateFake) Enable() error                         { return nil }
func (f *rotateFake) Disable() error                        { return nil }
func (f *rotateFake) Remove() error                         { return nil }
func (f *rotateFake) Ping(string) bool                      { return true }
func (f *rotateFake) WstunnelPath() (string, error)         { return "", nil }
func (f *rotateFake) InstallWstunnel() (string, error)      { return "", nil }

// TestRotatePinWalksRoutes proves sustained probe failure moves the Aegis pin
// across candidates instead of staying stuck on a dead interface.
func TestRotatePinWalksRoutes(t *testing.T) {
	fake := &rotateFake{routes: []Route{
		{Iface: "eth0", Gateway: "192.168.1.1"},
		{Iface: "wlan0", Gateway: "192.168.2.1"},
	}}
	s := newSupervisor(fake, nil, nil, log.New(os.Stderr, "test: ", 0), true, true)
	s.routes = fake.routes
	s.pinIdx = 0

	s.rotatePin()
	if s.pinIdx != 1 {
		t.Fatalf("pinIdx = %d, want 1", s.pinIdx)
	}
	if len(fake.repins) != 1 || fake.repins[0] != [2]string{"192.168.2.1", "wlan0"} {
		t.Fatalf("repins = %v, want gateway+iface of wlan0", fake.repins)
	}

	s.rotatePin()
	if s.pinIdx != 0 {
		t.Fatalf("pinIdx wrapped = %d, want 0", s.pinIdx)
	}
}

// TestRotatePinSingleRouteRepins proves a lone route re-applies the same pin
// rather than doing nothing.
func TestRotatePinSingleRouteRepins(t *testing.T) {
	fake := &rotateFake{routes: []Route{{Iface: "eth0", Gateway: "192.168.1.1"}}}
	s := newSupervisor(fake, nil, nil, log.New(os.Stderr, "test: ", 0), true, true)
	s.routes = fake.routes

	s.rotatePin()
	if len(fake.repins) != 1 {
		t.Fatalf("repins = %d, want 1 re-applied pin", len(fake.repins))
	}
}

// TestRotatePinNoRoutesLogs proves an empty table does not panic.
func TestRotatePinNoRoutesLogs(t *testing.T) {
	fake := &rotateFake{routes: nil, err: errors.New("no routes")}
	s := newSupervisor(fake, nil, nil, log.New(os.Stderr, "test: ", 0), true, true)
	s.rotatePin()
	if len(fake.repins) != 0 {
		t.Fatalf("repins = %d, want 0 with no routes", len(fake.repins))
	}
}
