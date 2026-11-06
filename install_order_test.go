package main

import (
	"errors"
	"strings"
	"testing"
)

type installFake struct {
	routeErr  error
	toolsErr  error
	configErr error
	secureErr error

	stopCalls  int
	startCalls int
}

func (f *installFake) RequirePrivilege() error { return nil }
func (f *installFake) DefaultRoute() (string, string, error) {
	if f.routeErr != nil {
		return "", "", f.routeErr
	}
	return "eth0", "192.168.1.1", nil
}
func (f *installFake) DefaultRoutes() ([]Route, error) {
	return []Route{{Iface: "eth0", Gateway: "192.168.1.1"}}, nil
}
func (f *installFake) InstallTools() error {
	if f.toolsErr != nil {
		return f.toolsErr
	}
	return nil
}
func (f *installFake) WriteTunnelConfig(tunnelConfig) (bool, error) {
	if f.configErr != nil {
		return false, f.configErr
	}
	return false, nil
}
func (f *installFake) StartTunnel() error                 { return nil }
func (f *installFake) StopTunnel() error                  { return nil }
func (f *installFake) TunnelUp() bool                     { return false }
func (f *installFake) TunnelConfigured() bool             { return false }
func (f *installFake) EnsureEndpoint(string) error        { return nil }
func (f *installFake) RepinEndpoint(string, string) error { return nil }
func (f *installFake) ApplyDNS(string, string) error      { return nil }
func (f *installFake) EnsureDNS(string, string) error     { return nil }
func (f *installFake) SecureInstallDir() error {
	if f.secureErr != nil {
		return f.secureErr
	}
	return nil
}
func (f *installFake) InstallService(string, []string) error { return nil }
func (f *installFake) StartService() error {
	f.startCalls++
	return nil
}
func (f *installFake) StopService() error {
	f.stopCalls++
	return nil
}
func (f *installFake) Enable() error                    { return nil }
func (f *installFake) Disable() error                   { return nil }
func (f *installFake) Remove() error                    { return nil }
func (f *installFake) Ping(string) bool                 { return true }
func (f *installFake) WstunnelPath() (string, error)    { return "", nil }
func (f *installFake) InstallWstunnel() (string, error) { return "", nil }

// TestInstallRefusesBeforeStopping proves validation failures exit before
// the running supervisor is touched: with DNS pointed at the listener,
// stopping first would kill all name resolution for a typo.
func TestInstallRefusesBeforeStopping(t *testing.T) {
	cases := []struct {
		name string
		args []string
		fake *installFake
		want string
	}{
		{"bad key", []string{"--key", "not-base64"}, &installFake{}, "valid base64"},
		{"bad ip", []string{"--key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "--ip", "999.1.1.1"}, &installFake{}, "invalid tunnel address"},
		{"no route", []string{"--key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, &installFake{routeErr: errors.New("no route")}, "default route"},
		{"tools fail", []string{"--key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, &installFake{toolsErr: errors.New("no package manager")}, "package manager"},
	}
	for _, tc := range cases {
		if err := runInstall(tc.fake, tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.want)
		}
		if tc.fake.stopCalls != 0 {
			t.Errorf("%s: StopService called %d times, want 0 (refuse before changing anything)", tc.name, tc.fake.stopCalls)
		}
	}
}

// TestInstallRestartsPreviousService proves a failure after the stop puts
// the old service back, so the resolver is not stranded on a dead listener.
// (Which exact step fails depends on the environment; what matters is the
// stop-once/restart-once pairing on any pre-service error.)
func TestInstallRestartsPreviousService(t *testing.T) {
	fake := &installFake{secureErr: errors.New("acl failed")}
	err := runInstall(fake, []string{"--key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "--no-tunnel"})
	if err == nil {
		t.Fatal("expected install to fail after stopping the service")
	}
	if fake.stopCalls != 1 {
		t.Errorf("StopService called %d times, want 1", fake.stopCalls)
	}
	if fake.startCalls != 1 {
		t.Errorf("StartService called %d times, want 1 restart of the previous service", fake.startCalls)
	}
}
