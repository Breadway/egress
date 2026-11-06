package main

import (
	"bytes"
	"os"
	"strings"
)

// Route is one default route: the interface identifier plus its gateway.
// The identifier convention matches DefaultRoute (device name on Linux and
// Darwin, interface index on Windows).
type Route struct {
	Iface   string
	Gateway string
}

// platform is the per-OS surface. Everything that differs between Linux and
// Windows lives behind it so the supervisor and installer stay shared.
type platform interface {
	// RequirePrivilege fails unless the process can change network state.
	RequirePrivilege() error

	// DefaultRoute returns the interface identifier and the default gateway.
	// On Windows the identifier is the interface index as a decimal string.
	DefaultRoute() (iface, gateway string, err error)

	// DefaultRoutes returns every default route, best first. The supervisor
	// pins Aegis traffic to the first one and fails over to the rest when
	// probes keep failing, so a default route via a dead interface cannot
	// strand the tunnel, DNS and fallback all at once.
	DefaultRoutes() ([]Route, error)

	// InstallTools installs the WireGuard runtime if it is missing.
	InstallTools() error

	// WriteTunnelConfig writes the tunnel configuration. On Windows it writes
	// both the direct and relay variants. It reports whether the on-disk
	// config differs from what was there before, so install can bounce a
	// live tunnel running a stale identity instead of leaving it in place
	// while verification reports the new one.
	WriteTunnelConfig(tunnelConfig) (changed bool, err error)

	// SecureInstallDir restricts the install directory to administrators.
	// It must hold in every install mode, including --no-tunnel, because the
	// directory always receives the installed binary, whose embedded key is
	// recoverable with strings. Failures are fatal: a permissive directory
	// must not pass silently.
	SecureInstallDir() error

	StartTunnel() error
	StopTunnel() error
	TunnelUp() bool

	// TunnelConfigured reports whether a tunnel config exists on this machine.
	TunnelConfigured() bool

	// EnsureEndpoint makes the endpoint the given address, doing nothing if it
	// already is. This is cheap on Linux and a service swap on Windows.
	EnsureEndpoint(endpoint string) error

	// RepinEndpoint re-points the Aegis address at the current default
	// gateway after a network change. The initial pin happens at tunnel
	// bring-up (PostUp on Linux, route add on Windows); without a refresh
	// here, a WiFi-to-Ethernet roam strands all Aegis traffic on the dead
	// interface while everything else follows the new default route.
	RepinEndpoint(gateway, iface string) error

	// ApplyDNS sets the system resolver to the local DoH listener.
	ApplyDNS(iface, gateway string) error
	// EnsureDNS re-applies it if DHCP or a reconnect reset it.
	EnsureDNS(iface, gateway string) error

	InstallService(exePath string, args []string) error
	StartService() error
	StopService() error
	// Enable allows the boot service or task to start again.
	Enable() error

	// Disable stops the resolver and the tunnel now, prevents them from
	// starting at boot, and restores the previous resolver settings. Configs,
	// logs and the binary stay on disk so Enable or a reinstall is cheap.
	Disable() error

	// Remove does everything Disable does, then deletes the configs, wstunnel,
	// log and the installed binary. The running binary itself is reported
	// rather than deleted when the platform cannot unlink it.
	Remove() error

	Ping(host string) bool

	WstunnelPath() (string, error)
	InstallWstunnel() (string, error)
}

// dnsServersPointAtListener reports whether a DNS server listing (one
// address per line, as printed by networksetup or Get-DnsClientServerAddress)
// still contains our local listener.
func dnsServersPointAtListener(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "127.0.0.1" {
			return true
		}
	}
	return false
}

// writeFileChanged writes data to path with mode 0600 and reports whether
// the previous contents differed. A missing file counts as changed, so first
// installs always bounce. Pure apart from the file itself, and unit-tested.
func writeFileChanged(path string, data []byte) (bool, error) {
	previous, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return false, err
	}
	return os.IsNotExist(err) || !bytes.Equal(previous, data), nil
}
