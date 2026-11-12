package egress

import (
	"context"
	"egress/internal/doh"
	"log"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type dnsWatchdogFake struct {
	ensureCalls int32
	applyCalls  int32
	routes      []Route
}

func (f *dnsWatchdogFake) RequirePrivilege() error                      { return nil }
func (f *dnsWatchdogFake) DefaultRoute() (string, string, error)        { return "eth0", "192.168.1.1", nil }
func (f *dnsWatchdogFake) DefaultRoutes() ([]Route, error)              { return f.routes, nil }
func (f *dnsWatchdogFake) InstallTools() error                          { return nil }
func (f *dnsWatchdogFake) WriteTunnelConfig(tunnelConfig) (bool, error) { return false, nil }
func (f *dnsWatchdogFake) StartTunnel() error                           { return nil }
func (f *dnsWatchdogFake) StopTunnel() error                            { return nil }
func (f *dnsWatchdogFake) TunnelUp() bool                               { return false }
func (f *dnsWatchdogFake) TunnelConfigured() bool                       { return false }
func (f *dnsWatchdogFake) EnsureEndpoint(string) error                  { return nil }
func (f *dnsWatchdogFake) RepinEndpoint(string, string) error           { return nil }
func (f *dnsWatchdogFake) ApplyDNS(string, string) error {
	atomic.AddInt32(&f.applyCalls, 1)
	return nil
}
func (f *dnsWatchdogFake) EnsureDNS(string, string) error {
	atomic.AddInt32(&f.ensureCalls, 1)
	return nil
}

// SecureInstallDir is a no-op here to satisfy the platform interface; the
// DNS watchdog never touches the install directory.
func (f *dnsWatchdogFake) SecureInstallDir() error               { return nil }
func (f *dnsWatchdogFake) InstallService(string, []string) error { return nil }
func (f *dnsWatchdogFake) StartService() error                   { return nil }
func (f *dnsWatchdogFake) StopService() error                    { return nil }
func (f *dnsWatchdogFake) ServiceActive() bool                   { return true }
func (f *dnsWatchdogFake) LivePublicKey() (string, error)        { return "", nil }
func (f *dnsWatchdogFake) Enable() error                         { return nil }
func (f *dnsWatchdogFake) Disable() error                        { return nil }
func (f *dnsWatchdogFake) Remove() error                         { return nil }
func (f *dnsWatchdogFake) Ping(string) bool                      { return true }
func (f *dnsWatchdogFake) WstunnelPath() (string, error)         { return "", nil }
func (f *dnsWatchdogFake) InstallWstunnel() (string, error)      { return "", nil }

// TestDNSLoopMaintainsResolver proves the DNS-only loop re-applies the
// resolver: without it a DHCP renew silently drops protection.
func TestDNSLoopMaintainsResolver(t *testing.T) {
	fake := &dnsWatchdogFake{routes: []Route{{Iface: "eth0", Gateway: "192.168.1.1"}}}
	resolver := doh.New("", log.New(os.Stderr, "test: ", 0))
	wst := newWstunnelProc("", log.New(os.Stderr, "test: ", 0))
	s := newSupervisor(fake, resolver, wst, log.New(os.Stderr, "test: ", 0), false, false)
	s.iface, s.gateway = "eth0", "192.168.1.1"

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { s.dnsLoop(ctx); close(done) }()
	<-done

	if got := atomic.LoadInt32(&fake.ensureCalls); got == 0 {
		t.Error("dnsLoop never called EnsureDNS; DNS-only machines would lose the resolver after DHCP changes")
	}
}
