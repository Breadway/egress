//go:build darwin

package platform

import (
	"egress/internal/assets"
	"egress/internal/core"
	"egress/internal/logx"
	"egress/internal/wstunnel"
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
	darwinWGPath    = "/etc/wireguard/" + core.WGInterface + ".conf"
	darwinWGBak     = "/etc/wireguard/" + core.WGInterface + ".conf.egress.bak"
	darwinLogPath   = "/var/log/egress.log"
)

// SHA-256 of the pinned wstunnel 11.1.0 darwin binaries, per arch. Kept
// here (not in the delivery-tagged asset files) so dev builds that extract
// nothing still verify downloads against the same pins.
const (
	wstunnelDarwinAmd64SHA256 = "72349e8eda9b80762e809b51dbe3c81aea8094b57da6ab6bb97274f048be4adb"
	wstunnelDarwinArm64SHA256 = "3c814a9b16481b6b17b9ea02b679b8b21454788da6c61366c4d26fca823c9feb"
)

// wstunnelDarwinSHA selects the pin matching this build's arch, so
// InstallWstunnel and Remove agree on what counts as ours.
func wstunnelDarwinSHA() string {
	if runtime.GOARCH == "amd64" {
		return wstunnelDarwinAmd64SHA256
	}
	return wstunnelDarwinArm64SHA256
}

type darwinPlatform struct{}

func New() Interface { return darwinPlatform{} }

// spoolDir holds the pending install report. Both install and the boot
// service run as root on macOS, so the shared temp directory works.
func spoolDir() string { return os.TempDir() }

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
	out, err := logx.ExecLogged("netstat", "-rn", "-f", "inet")
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
	out, err := logx.ExecLogged("networksetup", "-listallhardwareports")
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
		if err := logx.RunLogged("sudo", "-u", sudoUser, brew, "install", "wireguard-tools"); err == nil {
			if _, err := exec.LookPath("wg"); err == nil {
				return nil
			}
		}
		return errors.New("wireguard-tools is required; run as your normal user: brew install wireguard-tools")
	}
	return errors.New("wireguard-tools is required and Homebrew will not run as root; run as your normal user: brew install wireguard-tools")
}

func (darwinPlatform) WriteTunnelConfig(c core.TunnelConfig) (bool, error) {
	if err := os.MkdirAll(darwinWGDir, 0700); err != nil {
		return false, err
	}
	if err := BackupForeignConfig(darwinWGPath, darwinWGBak); err != nil {
		return false, err
	}
	// No Table/PostUp extras: wg-quick on Darwin adds the endpoint host route
	// itself before installing the AllowedIPs routes.
	return WriteFileChanged(darwinWGPath, []byte(core.RenderWGConfig(c)))
}

func (p darwinPlatform) StartTunnel() error {
	if p.TunnelUp() {
		if p.hasOurPeer() {
			return nil
		}
		logx.Debugf("wg0 exists without our peer; replacing it")
		_ = logx.RunLogged("wg-quick", "down", core.WGInterface)
	}
	return logx.RunLogged("wg-quick", "up", core.WGInterface)
}

// LivePublicKey returns the public key of the running tunnel interface.
func (darwinPlatform) LivePublicKey() (string, error) {
	out, err := exec.Command("wg", "show", core.WGInterface, "public-key").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// hasOurPeer reports whether the live interface carries our Aegis peer.
func (darwinPlatform) hasOurPeer() bool {
	out, err := exec.Command("wg", "show", core.WGInterface, "peers").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == core.AegisPublicKey {
			return true
		}
	}
	return false
}

func (p darwinPlatform) StopTunnel() error {
	_ = logx.RunLogged("wg-quick", "down", core.WGInterface)
	if p.TunnelUp() {
		return fmt.Errorf("wg0 is still up after stopping the tunnel")
	}
	return nil
}

func (darwinPlatform) TunnelUp() bool {
	return exec.Command("ifconfig", core.WGInterface).Run() == nil
}

func (darwinPlatform) TunnelConfigured() bool {
	_, err := os.Stat(darwinWGPath)
	return err == nil
}

// SecureInstallDir is a no-op on macOS: the install directory is the shared
// /usr/local/bin, which must keep its system ACLs.
func (darwinPlatform) SecureInstallDir() error { return nil }

func (darwinPlatform) EnsureEndpoint(endpoint string) error {
	out, err := logx.ExecLogged("wg", "show", core.WGInterface, "endpoints")
	if err != nil {
		return fmt.Errorf("read wireguard endpoints: %w", err)
	}
	current := ""
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == core.AegisPublicKey {
			current = fields[1]
			break
		}
	}
	if current == endpoint {
		logx.Debugf("endpoint already %s", endpoint)
		return nil
	}
	logx.Debugf("endpoint %s -> %s", current, endpoint)
	return logx.RunLogged("wg", "set", core.WGInterface, "peer", core.AegisPublicKey, "endpoint", endpoint)
}

// RepinEndpoint re-points the Aegis address at the new gateway. wg-quick owns
// an endpoint route from bring-up time; the delete-then-add replaces it so a
// roam cannot strand Aegis traffic on the old gateway.
func (darwinPlatform) RepinEndpoint(gateway, iface string) error {
	if gateway == "" {
		return fmt.Errorf("no default gateway to pin %s to", core.AegisIPv4)
	}
	_ = logx.RunLogged("route", "delete", "-host", core.AegisIPv4)
	return logx.RunLogged("route", "add", "-host", core.AegisIPv4, gateway)
}

func (darwinPlatform) ApplyDNS(iface, gateway string) error {
	service, err := serviceForDevice(iface)
	if err != nil {
		return err
	}
	return logx.RunLogged("networksetup", "-setdnsservers", service, "127.0.0.1")
}

func (darwinPlatform) EnsureDNS(iface, gateway string) error {
	service, err := serviceForDevice(iface)
	if err != nil {
		return nil
	}
	out, err := logx.ExecLogged("networksetup", "-getdnsservers", service)
	if err == nil && strings.Contains(string(out), "127.0.0.1") {
		return nil
	}
	return logx.RunLogged("networksetup", "-setdnsservers", service, "127.0.0.1")
}

func (darwinPlatform) restoreDNS() error {
	iface, _, err := (darwinPlatform{}).DefaultRoute()
	if err != nil {
		return fmt.Errorf("find the default route: %w", err)
	}
	service, err := serviceForDevice(iface)
	if err != nil {
		return err
	}
	if err := logx.RunLogged("networksetup", "-setdnsservers", service, "Empty"); err != nil {
		return fmt.Errorf("reset DNS on %s: %w", service, err)
	}
	// Read back: the adapter must not still point at our listener, or
	// disable would claim success with dead DNS.
	out, err := exec.Command("networksetup", "-getdnsservers", service).Output()
	if err != nil {
		return fmt.Errorf("read back DNS on %s: %w", service, err)
	}
	if DNSServersPointAtListener(string(out)) {
		return fmt.Errorf("%s still points at the egress listener", service)
	}
	return nil
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
	_ = logx.RunLogged("launchctl", "bootout", "system/"+darwinLabel)
	return logx.RunLogged("launchctl", "bootstrap", "system", darwinPlistPath)
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
	return logx.RunLogged("launchctl", "kickstart", "-k", "system/"+darwinLabel)
}

func (darwinPlatform) StopService() error {
	_ = logx.RunLogged("launchctl", "bootout", "system/"+darwinLabel)
	return nil
}

// ServiceActive is a quiet check: verification calls it on every run and a
// failing service must not spam the log.
func (darwinPlatform) ServiceActive() bool {
	out, err := exec.Command("launchctl", "print", "system/"+darwinLabel).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "state = running")
}

func (darwinPlatform) Enable() error {
	if _, err := os.Stat(darwinPlistPath); err != nil {
		return errors.New("egress is not installed; run install first")
	}
	if err := logx.RunLogged("launchctl", "enable", "system/"+darwinLabel); err != nil {
		return err
	}
	return logx.RunLogged("launchctl", "kickstart", "-k", "system/"+darwinLabel)
}

// Disable stops the resolver and the tunnel now, prevents both from starting
// at boot, and puts the adapter back on DHCP-provided DNS. Configs and logs
// stay so Enable is cheap.
func (p darwinPlatform) Disable() error {
	_ = p.StopService()
	_ = logx.RunLogged("launchctl", "disable", "system/"+darwinLabel)
	_ = p.StopTunnel()
	return p.restoreDNS()
}

// Remove is Disable plus the file system.
func (p darwinPlatform) Remove() error {
	_ = p.Disable()
	_ = os.Remove(darwinPlistPath)
	if restored, _ := RestoreBackedConfig(darwinWGPath, darwinWGBak); restored {
		logx.Debugf("restored the pre-existing %s", darwinWGPath)
	} else {
		_ = os.Remove(darwinWGPath)
	}

	logx.Close()
	_ = os.Remove(darwinLogPath)
	_ = os.Remove(darwinLogPath + ".old")

	if wstunnel.WstunnelIsOurs(filepath.Join(core.InstallDir(), "wstunnel"), wstunnelDarwinSHA()) {
		_ = os.Remove(filepath.Join(core.InstallDir(), "wstunnel"))
	} else {
		fmt.Printf("leaving %s: not installed by this tool\n", filepath.Join(core.InstallDir(), "wstunnel"))
	}
	RemoveInstalledBinary()
	return nil
}

func (darwinPlatform) Ping(host string) bool {
	return logx.RunLogged("ping", "-c", "2", "-t", "2", "-i", "0.5", "-n", "-q", host) == nil
}

func (darwinPlatform) WstunnelPath() (string, error) { return wstunnel.Find() }

// InstallWstunnel extracts the embedded fallback client. A dev build without
// embedded assets still falls back to the pinned download.
func (darwinPlatform) InstallWstunnel() (string, error) {
	if len(assets.Wstunnel) > 0 {
		dest := filepath.Join(core.InstallDir(), wstunnel.ExeName())
		if err := core.ExtractEmbedded(dest, assets.Wstunnel, wstunnelDarwinSHA()); err != nil {
			return "", fmt.Errorf("extract bundled wstunnel: %w", err)
		}
		if err := os.Chmod(dest, 0755); err != nil {
			return "", err
		}
		return dest, nil
	}
	return wstunnel.Ensure()
}

func Diagnose(w io.Writer) error {
	fmt.Fprintf(w, "  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if _, err := exec.LookPath("wg"); err == nil {
		fmt.Fprintf(w, "  wireguard-tools: present\n")
	} else {
		fmt.Fprintf(w, "  wireguard-tools: not found (brew install wireguard-tools)\n")
	}

	section(w, "default route")
	show(w, "route", "-n", "get", "default")

	section(w, "adapter dns")
	if iface, _, err := (darwinPlatform{}).DefaultRoute(); err == nil {
		if service, err := serviceForDevice(iface); err == nil {
			show(w, "networksetup", "-getdnsservers", service)
		} else {
			fmt.Fprintf(w, "  %v\n", err)
		}
	}

	section(w, "wireguard")
	show(w, "wg", "show", core.WGInterface)

	section(w, "listeners")
	show(w, "sh", "-c", "netstat -anv 2>/dev/null | grep -E '\\.(7103|7108)' || echo none")

	section(w, "launchd")
	show(w, "sh", "-c", "launchctl list 2>/dev/null | grep -E 'egress' || echo not loaded")

	section(w, "tunnel probe")
	show(w, "ping", "-c", "2", "-t", "2", "-n", core.AegisTunnelIP)

	section(w, "wstunnel")
	show(w, "sh", "-c", "command -v wstunnel || ls -l /usr/local/bin/wstunnel 2>/dev/null || echo not found")

	section(w, "log tail")
	logx.Tail(w, logPath(), 40)
	return nil
}
