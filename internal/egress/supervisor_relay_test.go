package egress

import (
	"errors"
	"log"
	"os"
	"testing"
)

type relayFake struct {
	pingOK bool
}

func (f *relayFake) RequirePrivilege() error               { return nil }
func (f *relayFake) DefaultRoute() (string, string, error) { return "", "", errors.New("none") }
func (f *relayFake) DefaultRoutes() ([]Route, error)       { return nil, errors.New("none") }
func (f *relayFake) InstallTools() error                   { return nil }
func (f *relayFake) WriteTunnelConfig(tunnelConfig) (bool, error) {
	return false, nil
}
func (f *relayFake) StartTunnel() error                    { return nil }
func (f *relayFake) StopTunnel() error                     { return nil }
func (f *relayFake) TunnelUp() bool                        { return false }
func (f *relayFake) TunnelConfigured() bool                { return false }
func (f *relayFake) EnsureEndpoint(string) error           { return nil }
func (f *relayFake) RepinEndpoint(string, string) error    { return nil }
func (f *relayFake) ApplyDNS(string, string) error         { return nil }
func (f *relayFake) EnsureDNS(string, string) error        { return nil }
func (f *relayFake) SecureInstallDir() error               { return nil }
func (f *relayFake) ServiceActive() bool                   { return true }
func (f *relayFake) LivePublicKey() (string, error)        { return "", nil }
func (f *relayFake) InstallService(string, []string) error { return nil }
func (f *relayFake) StartService() error                   { return nil }
func (f *relayFake) StopService() error                    { return nil }
func (f *relayFake) Enable() error                         { return nil }
func (f *relayFake) Disable() error                        { return nil }
func (f *relayFake) Remove() error                         { return nil }
func (f *relayFake) Ping(string) bool                      { return f.pingOK }
func (f *relayFake) WstunnelPath() (string, error)         { return "", nil }
func (f *relayFake) InstallWstunnel() (string, error)      { return "", nil }

// TestProbeRelayCountsFailures proves the relay path gets its own health
// signal: a blackholed WebSocket with a listening port must count up toward
// a restart instead of sitting silent until the next UDP trial.
func TestProbeRelayCountsFailures(t *testing.T) {
	newSup := func(pingOK bool) *supervisor {
		return newSupervisor(&relayFake{pingOK: pingOK}, nil, nil,
			log.New(os.Stderr, "test: ", 0), true, true)
	}

	down := newSup(false)
	if down.probeRelay() {
		t.Fatal("failing ping must report down")
	}
	if down.relayFailures != 1 {
		t.Fatalf("relayFailures = %d, want 1", down.relayFailures)
	}
	if down.probeRelay() {
		t.Fatal("failing ping must report down again")
	}
	if down.relayFailures != 2 {
		t.Fatalf("relayFailures = %d, want 2 (the restart threshold)", down.relayFailures)
	}

	up := newSup(true)
	up.relayFailures = 1
	if !up.probeRelay() {
		t.Fatal("passing ping must report up")
	}
	if up.relayFailures != 0 {
		t.Fatalf("relayFailures = %d, want reset to 0", up.relayFailures)
	}
}
