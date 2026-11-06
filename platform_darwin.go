//go:build darwin

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	darwinLabel     = "egress"
	darwinPlistPath = "/Library/LaunchDaemons/egress.plist"
	darwinWGDir     = "/etc/wireguard"
	darwinWGPath    = "/etc/wireguard/" + wgInterface + ".conf"
	darwinLogPath   = "/var/log/egress.log"
)

type darwinPlatform struct{}

func newPlatform() platform { return darwinPlatform{} }

func installDir() string { return "/usr/local/bin" }

func logPath() string { return darwinLogPath }

func (darwinPlatform) RequirePrivilege() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root (try sudo)")
	}
	return nil
}

// DefaultRoute parses `route -n get default`. The interface identifier is the
// BSD device name (for example en0), matching the Linux convention.
func (p darwinPlatform) DefaultRoute() (string, string, error) {
	routes, err := p.DefaultRoutes()
	if err != nil {
		return "", "", err
	}
	return routes[0].Iface, routes[0].Gateway, nil
}

// parseDefaultRoutesDarwin parses `netstat -rn` default lines, in kernel
// priority order. Pure and unit-tested.
func parseDefaultRoutesDarwin(out string) []Route {
	var routes []Route
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" {
			continue
		}
		gateway, iface := fields[1], fields[len(fields)-1]
		if net.ParseIP(gateway) == nil || iface == "" || strings.Contains(iface, ":") {
			continue
		}
		routes = append(routes, Route{Iface: iface, Gateway: gateway})
	}
	return routes
}

func (darwinPlatform) DefaultRoutes() ([]Route, error) {
	out, err := execLogged("netstat", "-rn", "-f", "inet")
	if err != nil {
		return nil, err
	}
	routes := parseDefaultRoutesDarwin(string(out))
	if len(routes) == 0 {
		return nil, errors.New("no default route found")
	}
	return routes, nil
}

// serviceForDevice maps a BSD device (en0) to its networksetup service name
// ("Wi-Fi") by parsing `networksetup -listallhardwareports`.
func serviceForDevice(device string) (string, error) {
	out, err := execLogged("networksetup", "-listallhardwareports")
	if err != nil {
		return "", err
	}
	service := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "Hardware Port:"); ok {
			service = strings.TrimSpace(rest)
		}
		if rest, ok := strings.CutPrefix(line, "Device:"); ok {
			if strings.TrimSpace(rest) == device {
				if service == "" {
					return "", fmt.Errorf("no service name for device %s", device)
				}
				return service, nil
			}
			service = ""
		}
	}
	return "", fmt.Errorf("no network service for device %s", device)
}

func (darwinPlatform) InstallTools() error {
	if _, err := exec.LookPath("wg"); err == nil {
		return nil
	}
	brew := ""
	for _, candidate := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			brew = candidate
			break
		}
	}
	if brew == "" {
		return errors.New("wireguard-tools is required; install Homebrew, then run: brew install wireguard-tools")
	}
	// Homebrew refuses to run as root, so install as the invoking user when
	// this runs under sudo.
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		if err := runLogged("sudo", "-u", sudoUser, brew, "install", "wireguard-tools"); err == nil {
			if _, err := exec.LookPath("wg"); err == nil {
				return nil
			}
		}
		return errors.New("wireguard-tools is required; run as your normal user: brew install wireguard-tools")
	}
	return errors.New("wireguard-tools is required and Homebrew will not run as root; run as your normal user: brew install wireguard-tools")
}

func (darwinPlatform) WriteTunnelConfig(c tunnelConfig) error {
	if err := os.MkdirAll(darwinWGDir, 0700); err != nil {
		return err
	}
	// No Table/PostUp extras: wg-quick on Darwin adds the endpoint host route
	// itself before installing the AllowedIPs routes.
	return os.WriteFile(darwinWGPath, []byte(renderWGConfig(c)), 0600)
}

func (p darwinPlatform) StartTunnel() error {
	if p.TunnelUp() {
		if p.hasOurPeer() {
			return nil
		}
		debugf("wg0 exists without our peer; replacing it")
		_ = runLogged("wg-quick", "down", wgInterface)
	}
	return runLogged("wg-quick", "up", wgInterface)
}

// hasOurPeer reports whether the live interface carries our Aegis peer.
func (darwinPlatform) hasOurPeer() bool {
	out, err := exec.Command("wg", "show", wgInterface, "peers").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == aegisPublicKey {
			return true
		}
	}
	return false
}

func (darwinPlatform) StopTunnel() error {
	_ = runLogged("wg-quick", "down", wgInterface)
	return nil
}

func (darwinPlatform) TunnelUp() bool {
	return exec.Command("ifconfig", wgInterface).Run() == nil
}

func (darwinPlatform) TunnelConfigured() bool {
	_, err := os.Stat(darwinWGPath)
	return err == nil
}

// SecureInstallDir is a no-op on macOS: the install directory is the shared
// /usr/local/bin, which must keep its system ACLs.
func (darwinPlatform) SecureInstallDir() error { return nil }

func (darwinPlatform) EnsureEndpoint(endpoint string) error {
	out, err := execLogged("wg", "show", wgInterface, "endpoints")
	if err != nil {
		return fmt.Errorf("read wireguard endpoints: %w", err)
	}
	current := ""
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == aegisPublicKey {
			current = fields[1]
			break
		}
	}
	if current == endpoint {
		debugf("endpoint already %s", endpoint)
		return nil
	}
	debugf("endpoint %s -> %s", current, endpoint)
	return runLogged("wg", "set", wgInterface, "peer", aegisPublicKey, "endpoint", endpoint)
}

// RepinEndpoint re-points the Aegis address at the new gateway. wg-quick owns
// an endpoint route from bring-up time; the delete-then-add replaces it so a
// roam cannot strand Aegis traffic on the old gateway.
func (darwinPlatform) RepinEndpoint(gateway, iface string) error {
	if gateway == "" {
		return fmt.Errorf("no default gateway to pin %s to", aegisIPv4)
	}
	_ = runLogged("route", "delete", "-host", aegisIPv4)
	return runLogged("route", "add", "-host", aegisIPv4, gateway)
}

func (darwinPlatform) ApplyDNS(iface, gateway string) error {
	service, err := serviceForDevice(iface)
	if err != nil {
		return err
	}
	return runLogged("networksetup", "-setdnsservers", service, "127.0.0.1")
}

func (darwinPlatform) EnsureDNS(iface, gateway string) error {
	service, err := serviceForDevice(iface)
	if err != nil {
		return nil
	}
	out, err := execLogged("networksetup", "-getdnsservers", service)
	if err == nil && strings.Contains(string(out), "127.0.0.1") {
		return nil
	}
	return runLogged("networksetup", "-setdnsservers", service, "127.0.0.1")
}

func (darwinPlatform) restoreDNS() {
	iface, _, err := (darwinPlatform{}).DefaultRoute()
	if err != nil {
		return
	}
	service, err := serviceForDevice(iface)
	if err != nil {
		return
	}
	_ = runLogged("networksetup", "-setdnsservers", service, "Empty")
}

func (darwinPlatform) InstallService(exePath string, args []string) error {
	quoted := make([]string, 0, len(args)+1)
	quoted = append(quoted, exePath)
	quoted = append(quoted, args...)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	b.WriteString("\t<key>Label</key>\n\t<string>" + darwinLabel + "</string>\n")
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, arg := range quoted {
		fmt.Fprintf(&b, "\t\t<string>%s</string>\n", plistEscape(arg))
	}
	b.WriteString("\t</array>\n")
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	b.WriteString("\t<key>KeepAlive</key>\n\t<true/>\n")
	b.WriteString("\t<key>ThrottleInterval</key>\n\t<integer>3</integer>\n")
	b.WriteString("</dict>\n</plist>\n")

	if err := os.WriteFile(darwinPlistPath, []byte(b.String()), 0644); err != nil {
		return err
	}
	_ = runLogged("launchctl", "bootout", "system/"+darwinLabel)
	return runLogged("launchctl", "bootstrap", "system", darwinPlistPath)
}

func plistEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
	)
	return r.Replace(s)
}

func (darwinPlatform) StartService() error {
	return runLogged("launchctl", "kickstart", "-k", "system/"+darwinLabel)
}

func (darwinPlatform) StopService() error {
	_ = runLogged("launchctl", "bootout", "system/"+darwinLabel)
	return nil
}

func (darwinPlatform) Enable() error {
	if _, err := os.Stat(darwinPlistPath); err != nil {
		return errors.New("egress is not installed; run install first")
	}
	if err := runLogged("launchctl", "enable", "system/"+darwinLabel); err != nil {
		return err
	}
	return runLogged("launchctl", "kickstart", "-k", "system/"+darwinLabel)
}

// Disable stops the resolver and the tunnel now, prevents both from starting
// at boot, and puts the adapter back on DHCP-provided DNS. Configs and logs
// stay so Enable is cheap.
func (p darwinPlatform) Disable() error {
	_ = p.StopService()
	_ = runLogged("launchctl", "disable", "system/"+darwinLabel)
	_ = p.StopTunnel()
	p.restoreDNS()
	return nil
}

// Remove is Disable plus the file system.
func (p darwinPlatform) Remove() error {
	_ = p.Disable()
	_ = os.Remove(darwinPlistPath)
	_ = os.Remove(darwinWGPath)

	closeLog()
	_ = os.Remove(darwinLogPath)
	_ = os.Remove(darwinLogPath + ".old")

	_ = os.Remove(filepath.Join(installDir(), "wstunnel"))
	removeInstalledBinary()
	return nil
}

func (darwinPlatform) Ping(host string) bool {
	return runLogged("ping", "-c", "2", "-t", "2", "-i", "0.5", "-n", "-q", host) == nil
}

func (darwinPlatform) WstunnelPath() (string, error) { return findWstunnel() }

// InstallWstunnel extracts the embedded fallback client. A dev build without
// embedded assets still falls back to the pinned download.
func (darwinPlatform) InstallWstunnel() (string, error) {
	if len(embeddedWstunnel) > 0 {
		dest := filepath.Join(installDir(), wstunnelExeName())
		if err := extractEmbedded(dest, embeddedWstunnel, wstunnelDarwinSHA256); err != nil {
			return "", fmt.Errorf("extract bundled wstunnel: %w", err)
		}
		if err := os.Chmod(dest, 0755); err != nil {
			return "", err
		}
		return dest, nil
	}
	return ensureWstunnel()
}

func writeDiagnosePlatform(w io.Writer) error {
	fmt.Fprintf(w, "  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if _, err := exec.LookPath("wg"); err == nil {
		fmt.Printf("  wireguard-tools: present\n")
	} else {
		fmt.Printf("  wireguard-tools: not found (brew install wireguard-tools)\n")
	}

	section(w, "default route")
	show(w, "route", "-n", "get", "default")

	section(w, "adapter dns")
	if iface, _, err := (darwinPlatform{}).DefaultRoute(); err == nil {
		if service, err := serviceForDevice(iface); err == nil {
			show(w, "networksetup", "-getdnsservers", service)
		} else {
			fmt.Printf("  %v\n", err)
		}
	}

	section(w, "wireguard")
	show(w, "wg", "show", wgInterface)

	section(w, "listeners")
	show(w, "sh", "-c", "netstat -anv 2>/dev/null | grep -E '\\.(7103|7108)' || echo none")

	section(w, "launchd")
	show(w, "sh", "-c", "launchctl list 2>/dev/null | grep -E 'egress' || echo not loaded")

	section(w, "tunnel probe")
	show(w, "ping", "-c", "2", "-t", "2", "-n", aegisTunnelIP)

	section(w, "wstunnel")
	show(w, "sh", "-c", "command -v wstunnel || ls -l /usr/local/bin/wstunnel 2>/dev/null || echo not found")

	section(w, "log tail")
	tailLog(w, 40)
	return nil
}
