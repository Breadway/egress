//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	linuxUnitPath    = "/etc/systemd/system/egress.service"
	linuxWGPath      = "/etc/wireguard/" + wgInterface + ".conf"
	linuxWGBak       = "/etc/wireguard/" + wgInterface + ".conf.egress.bak"
	linuxResolvedDir = "/etc/systemd/resolved.conf.d"
	linuxResolved    = linuxResolvedDir + "/egress.conf"
	linuxResolvConf  = "/etc/resolv.conf"
	linuxResolvBak   = "/etc/resolv.conf.egress.bak"
	linuxLogPath     = "/var/log/egress.log"

	// SHA-256 of the pinned wstunnel 11.1.0 linux/amd64 binary embedded at
	// build time. Delivery builds extract this instead of downloading.
	wstunnelLinuxSHA256 = "62b26d0ee0f2211cef15fa1b85173fe687bc6698121842bf324359b412afc151"
)

type linuxPlatform struct{}

func newPlatform() platform { return linuxPlatform{} }

func installDir() string { return "/usr/local/bin" }

// spoolDir holds the pending install report. Both install and the boot
// service run as root on Linux, so the shared temp directory works.
func spoolDir() string { return os.TempDir() }

func logPath() string { return linuxLogPath }

func (linuxPlatform) RequirePrivilege() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	return nil
}

func (p linuxPlatform) DefaultRoute() (string, string, error) {
	routes, err := p.DefaultRoutes()
	if err != nil {
		return "", "", err
	}
	return routes[0].Iface, routes[0].Gateway, nil
}

// parseDefaultRoutesLinux parses `ip route show default`, best metric first.
// Pure and unit-tested; the live command output is the only input.
func parseDefaultRoutesLinux(out []byte) ([]Route, error) {
	type candidate struct {
		route  Route
		metric int
	}
	var found []candidate
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "default" {
			continue
		}
		var gateway, iface string
		metric := 0
		for i := 1; i < len(fields)-1; i++ {
			switch fields[i] {
			case "via":
				gateway = fields[i+1]
			case "dev":
				iface = fields[i+1]
			case "metric":
				fmt.Sscanf(fields[i+1], "%d", &metric)
			}
		}
		if iface == "" || gateway == "" {
			continue
		}
		found = append(found, candidate{Route{Iface: iface, Gateway: gateway}, metric})
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].metric < found[j].metric })
	routes := make([]Route, 0, len(found))
	for _, c := range found {
		routes = append(routes, c.route)
	}
	return routes, nil
}

func (linuxPlatform) DefaultRoutes() ([]Route, error) {
	out, err := execLogged("ip", "route", "show", "default")
	if err != nil {
		return nil, err
	}
	routes, err := parseDefaultRoutesLinux(out)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, errors.New("no default route found")
	}
	return routes, nil
}

func (linuxPlatform) InstallTools() error {
	if _, err := exec.LookPath("wg"); err == nil {
		return nil
	}
	return installPackage("wireguard-tools")
}

func installPackage(name string) error {
	type manager struct {
		path string
		args []string
	}
	candidates := []manager{
		{"/usr/bin/apt-get", []string{"install", "-y", name}},
		{"/usr/bin/apt", []string{"install", "-y", name}},
		{"/usr/bin/pacman", []string{"-S", "--noconfirm", name}},
		{"/usr/bin/dnf", []string{"install", "-y", name}},
		{"/usr/bin/zypper", []string{"install", "-y", name}},
	}
	for _, m := range candidates {
		if _, err := os.Stat(m.path); err != nil {
			continue
		}
		if err := runLogged(m.path, m.args...); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("cannot install %s: no supported package manager found", name)
}

func (linuxPlatform) WriteTunnelConfig(c tunnelConfig) (bool, error) {
	if err := os.MkdirAll("/etc/wireguard", 0700); err != nil {
		return false, err
	}
	// A foreign wg0.conf (corporate VPN, another tool) is backed up before
	// it is replaced, so installing here cannot silently destroy it.
	if err := backupForeignConfig(linuxWGPath, linuxWGBak); err != nil {
		return false, err
	}
	return writeFileChanged(linuxWGPath, []byte(renderWGConfig(c)))
}

func (p linuxPlatform) StartTunnel() error {
	if p.TunnelUp() {
		if p.hasOurPeer() {
			return nil
		}
		// A foreign wg0 (NetworkManager autoconnect is a real example) would
		// make every later step operate on the wrong interface. Replace it.
		debugf("wg0 exists without our peer; replacing it")
		_ = runLogged("systemctl", "stop", "wg-quick@"+wgInterface)
		_ = runLogged("wg-quick", "down", wgInterface)
	}
	if err := runLogged("systemctl", "start", "wg-quick@"+wgInterface); err == nil {
		return nil
	}
	return runLogged("wg-quick", "up", wgInterface)
}

// hasOurPeer reports whether the live interface carries our Aegis peer.
func (linuxPlatform) hasOurPeer() bool {
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

func (linuxPlatform) StopTunnel() error {
	if err := runLogged("systemctl", "stop", "wg-quick@"+wgInterface); err != nil {
		_ = runLogged("wg-quick", "down", wgInterface)
	}
	return nil
}

func (linuxPlatform) TunnelUp() bool {
	_, err := os.Stat("/sys/class/net/" + wgInterface)
	return err == nil
}

func (linuxPlatform) TunnelConfigured() bool {
	_, err := os.Stat(linuxWGPath)
	return err == nil
}

// SecureInstallDir is a no-op on Linux: the install directory is the shared
// /usr/local/bin, which must keep its system ACLs.
func (linuxPlatform) SecureInstallDir() error { return nil }

func (linuxPlatform) EnsureEndpoint(endpoint string) error {
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

// pinEndpoint routes the Aegis address via the given gateway so handshakes,
// DoH and the fallback never enter the tunnel. PostUp runs the same command
// at bring-up; RepinEndpoint re-runs it after a roam.
func pinEndpoint(gateway, iface string) error {
	if gateway == "" || iface == "" {
		return fmt.Errorf("no default route to pin %s to", aegisIPv4)
	}
	return runLogged("ip", "route", "replace", aegisIPv4, "via", gateway, "dev", iface)
}

func (linuxPlatform) RepinEndpoint(gateway, iface string) error {
	return pinEndpoint(gateway, iface)
}

func (p linuxPlatform) ApplyDNS(iface, gateway string) error {
	if !resolvedActive() {
		// No systemd-resolved: resolv.conf is the only resolver state. Skip
		// the drop-in tree entirely so a later-installed resolved does not
		// suddenly honor a stale file, and skip the doomed restart.
		return writeResolvConf()
	}
	if err := os.MkdirAll(linuxResolvedDir, 0755); err != nil {
		return err
	}
	dropIn := "[Resolve]\nDNS=" + dohListenAddr + "\nFallbackDNS=\n"
	if err := os.WriteFile(linuxResolved, []byte(dropIn), 0644); err != nil {
		return err
	}
	if err := runLogged("systemctl", "restart", "systemd-resolved"); err != nil {
		// No systemd-resolved: point resolv.conf at the listener instead.
		return writeResolvConf()
	}
	_ = runLogged("resolvectl", "flush-caches")
	return nil
}

// resolvSymlinkPrefix marks a resolv.conf backup that records a symlink
// target instead of file contents. The backup is a single line, so a
// foreign file can only collide by containing exactly that line.
const resolvSymlinkPrefix = "egress-symlink "

// backupResolvConf saves confPath for later restore when this tool did not
// write it: a symlink is recorded as its target (writing through it would
// scribble on systemd-resolved or NetworkManager state), other contents are
// copied unless they already point at our listener. An existing backup wins.
func backupResolvConf(confPath, bakPath string) error {
	fi, err := os.Lstat(confPath)
	if err != nil {
		return nil
	}
	if _, err := os.Stat(bakPath); err == nil {
		return nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(confPath)
		if err != nil {
			return err
		}
		return os.WriteFile(bakPath, []byte(resolvSymlinkPrefix+target+"\n"), 0644)
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		return err
	}
	if strings.Contains(string(data), "127.0.0.1") {
		return nil
	}
	return os.WriteFile(bakPath, data, 0644)
}

// restoreResolvConf undoes backupResolvConf: a recorded symlink is
// re-created, saved contents are moved back. Anything else is left alone.
func restoreResolvConf(confPath, bakPath string) error {
	data, err := os.ReadFile(bakPath)
	if err != nil {
		return nil
	}
	if target, ok := strings.CutPrefix(string(data), resolvSymlinkPrefix); ok {
		target = strings.TrimSpace(target)
		_ = os.Remove(confPath)
		if err := os.Symlink(target, confPath); err != nil {
			return err
		}
		_ = os.Remove(bakPath)
		return nil
	}
	if err := os.Rename(bakPath, confPath); err != nil {
		return err
	}
	return nil
}

func writeResolvConf() error {
	return writeResolvConfAt(linuxResolvConf, linuxResolvBak)
}

// writeResolvConfAt points the resolver at the local listener, preserving a
// pre-existing symlink instead of writing through it or paving over it.
func writeResolvConfAt(confPath, bakPath string) error {
	if err := backupResolvConf(confPath, bakPath); err != nil {
		return err
	}
	if fi, err := os.Lstat(confPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(confPath); err != nil {
			return err
		}
	}
	return os.WriteFile(confPath, []byte("nameserver 127.0.0.1\noptions edns0 trust-ad\n"), 0644)
}

// resolvedActive reports whether systemd-resolved is running. Plain exec, no
// logging: EnsureDNS calls this every minute and a failing service would
// otherwise spam the log.
func resolvedActive() bool {
	return exec.Command("systemctl", "is-active", "--quiet", "systemd-resolved").Run() == nil
}

// resolvConfPointsAtListener reports whether resolv.conf already directs
// queries at the local DoH listener. Pure and unit-tested.
func resolvConfPointsAtListener(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "nameserver" && fields[1] == "127.0.0.1" {
			return true
		}
	}
	return false
}

func (p linuxPlatform) EnsureDNS(iface, gateway string) error {
	if !resolvedActive() {
		// Fallback path converges on resolv.conf contents: no rewrite when
		// the listener is already the resolver.
		if data, err := os.ReadFile(linuxResolvConf); err == nil && resolvConfPointsAtListener(data) {
			return nil
		}
		return p.ApplyDNS(iface, gateway)
	}
	data, err := os.ReadFile(linuxResolved)
	if err == nil && strings.Contains(string(data), dohListenAddr) {
		return nil
	}
	return p.ApplyDNS(iface, gateway)
}

func (linuxPlatform) InstallService(exePath string, args []string) error {
	unit := fmt.Sprintf(`[Unit]
Description=egress: DoH resolver and WireGuard exit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s %s
Restart=always
RestartSec=3
KillMode=control-group

[Install]
WantedBy=multi-user.target
`, exePath, strings.Join(args, " "))

	if err := os.WriteFile(linuxUnitPath, []byte(unit), 0644); err != nil {
		return err
	}
	if err := runLogged("systemctl", "daemon-reload"); err != nil {
		return err
	}
	return runLogged("systemctl", "enable", "egress.service")
}

func (linuxPlatform) StartService() error {
	return runLogged("systemctl", "restart", "egress.service")
}

func (linuxPlatform) StopService() error {
	_ = runLogged("systemctl", "stop", "egress.service")
	return nil
}

// ServiceActive is a quiet check: verification calls it on every run and a
// failing service must not spam the log.
func (linuxPlatform) ServiceActive() bool {
	return exec.Command("systemctl", "is-active", "--quiet", "egress.service").Run() == nil
}

func (linuxPlatform) Enable() error {
	if _, err := os.Stat(linuxUnitPath); err != nil {
		return errors.New("egress is not installed; run install first")
	}
	if err := runLogged("systemctl", "enable", "egress.service"); err != nil {
		return err
	}
	return runLogged("systemctl", "restart", "egress.service")
}

// Disable stops the resolver and the tunnel now, prevents both from starting
// at boot, and puts the system resolver back the way it was. Configs and logs
// stay so Enable is cheap.
func (p linuxPlatform) Disable() error {
	_ = p.StopService()
	_ = runLogged("systemctl", "disable", "egress.service")

	// The unit is only enabled by Enable or by an older setup, but disabling
	// it here guarantees the tunnel cannot come up on its own after this.
	_ = p.StopTunnel()
	_ = runLogged("systemctl", "disable", "wg-quick@"+wgInterface)

	return p.restoreDNS()
}

// Remove is Disable plus the file system. Everything this tool created goes,
// except a running binary the platform cannot unlink, which is reported.
func (p linuxPlatform) Remove() error {
	_ = p.Disable()

	_ = os.Remove(linuxUnitPath)
	_ = runLogged("systemctl", "daemon-reload")
	if restored, _ := restoreBackedConfig(linuxWGPath, linuxWGBak); restored {
		debugf("restored the pre-existing %s", linuxWGPath)
	} else {
		_ = os.Remove(linuxWGPath)
	}
	_ = os.Remove(linuxResolvBak)

	// Close the debug log before deleting it, or the inode would stay alive
	// until this process exits.
	closeLog()
	_ = os.Remove(linuxLogPath)
	_ = os.Remove(linuxLogPath + ".old")

	// Only remove the fallback client when this tool put it there: a
	// pre-existing wstunnel that findWstunnel reused is not ours to delete.
	if wstunnelIsOurs(filepath.Join(installDir(), "wstunnel"), wstunnelLinuxSHA256) {
		_ = os.Remove(filepath.Join(installDir(), "wstunnel"))
	} else {
		fmt.Printf("leaving %s: not installed by this tool\n", filepath.Join(installDir(), "wstunnel"))
	}
	removeInstalledBinary()
	return nil
}

// restoreDNS removes the local resolver drop-in and restores /etc/resolv.conf
// if this tool had rewritten it.
func (linuxPlatform) restoreDNS() error {
	if err := os.Remove(linuxResolved); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", linuxResolved, err)
	}
	hadBackup := false
	if _, err := os.Stat(linuxResolvBak); err == nil {
		hadBackup = true
		if err := restoreResolvConf(linuxResolvConf, linuxResolvBak); err != nil {
			return fmt.Errorf("restore %s: %w", linuxResolvConf, err)
		}
	}
	if err := runLogged("systemctl", "restart", "systemd-resolved"); err != nil {
		// No systemd-resolved is the common case there: resolv.conf is
		// the only resolver state, verified below. A present-but-broken
		// unit is a real failure, not an absence.
		if resolvedUnitPresent() {
			return fmt.Errorf("restart systemd-resolved: %w", err)
		}
	} else {
		_ = runLogged("resolvectl", "flush-caches")
	}
	if hadBackup {
		// Read back: the restored file must not point at our listener, or
		// disable would claim success with dead DNS.
		data, err := os.ReadFile(linuxResolvConf)
		if err != nil {
			return fmt.Errorf("read %s: %w", linuxResolvConf, err)
		}
		if resolvConfPointsAtListener(data) {
			return fmt.Errorf("%s still points at the egress listener", linuxResolvConf)
		}
	}
	return nil
}

// resolvedUnitPresent reports whether systemd-resolved is installed at all,
// separating a missing resolver (benign) from a broken one (fatal).
func resolvedUnitPresent() bool {
	out, err := exec.Command("systemctl", "show", "-p", "LoadState", "--value", "systemd-resolved").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "loaded"
}

func (linuxPlatform) Ping(host string) bool {
	return runLogged("ping", "-c", "2", "-W", "2", "-i", "0.5", "-n", "-q", host) == nil
}

func (linuxPlatform) WstunnelPath() (string, error) { return findWstunnel() }

// InstallWstunnel extracts the embedded fallback client. No target-side
// download is attempted when the delivery build carries the binary; a dev
// build without embedded assets still falls back to the pinned download.
func (linuxPlatform) InstallWstunnel() (string, error) {
	if len(embeddedWstunnel) > 0 {
		dest := filepath.Join(installDir(), wstunnelExeName())
		if err := extractEmbedded(dest, embeddedWstunnel, wstunnelLinuxSHA256); err != nil {
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

	section(w, "default route")
	show(w, "ip", "route", "show", "default")

	section(w, "resolver")
	show(w, "resolvectl", "status")

	section(w, "wireguard")
	show(w, "wg", "show", wgInterface)

	section(w, "listeners")
	show(w, "sh", "-c", "ss -lunp 2>/dev/null | grep -E ':(7103|7108)' || echo none")

	section(w, "tunnel probe")
	show(w, "ping", "-c", "2", "-W", "2", "-n", aegisTunnelIP)

	section(w, "wstunnel")
	show(w, "sh", "-c", "command -v wstunnel || ls -l /usr/local/bin/wstunnel 2>/dev/null || echo not found")

	section(w, "log tail")
	tailLog(w, 40)
	return nil
}
