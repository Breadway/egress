//go:build linux

package platform

import (
	"egress/internal/core"
	"egress/internal/logx"
	"egress/internal/wstunnel"
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
	linuxWGPath      = "/etc/wireguard/" + core.WGInterface + ".conf"
	linuxWGBak       = "/etc/wireguard/" + core.WGInterface + ".conf.egress.bak"
	linuxResolvedDir = "/etc/systemd/resolved.conf.d"
	linuxResolved    = linuxResolvedDir + "/egress.conf"
	linuxResolvConf  = "/etc/resolv.conf"
	linuxResolvBak   = "/etc/resolv.conf.egress.bak"
	linuxLogPath     = "/var/log/egress.log"

	tailscaleDNSMarker = "tailscale-dns-disabled"

	// SHA-256 of the pinned wstunnel 11.1.0 linux/amd64 binary embedded at
	// build time. Delivery builds extract this instead of downloading.
	wstunnelLinuxSHA256 = "62b26d0ee0f2211cef15fa1b85173fe687bc6698121842bf324359b412afc151"
)

type linuxPlatform struct{}

func New() Interface { return linuxPlatform{} }

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
	out, err := logx.ExecLogged("ip", "route", "show", "default")
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
		if err := logx.RunLogged(m.path, m.args...); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("cannot install %s: no supported package manager found", name)
}

func (linuxPlatform) WriteTunnelConfig(c core.TunnelConfig) (bool, error) {
	if err := os.MkdirAll("/etc/wireguard", 0700); err != nil {
		return false, err
	}
	// A foreign wg0.conf (corporate VPN, another tool) is backed up before
	// it is replaced, so installing here cannot silently destroy it.
	if err := BackupForeignConfig(linuxWGPath, linuxWGBak); err != nil {
		return false, err
	}
	return WriteFileChanged(linuxWGPath, []byte(core.RenderWGConfig(c)))
}

func (p linuxPlatform) StartTunnel() error {
	if p.TunnelUp() {
		if p.hasOurPeer() {
			return nil
		}
		// A foreign wg0 (NetworkManager autoconnect is a real example) would
		// make every later step operate on the wrong interface. Replace it.
		logx.Debugf("wg0 exists without our peer; replacing it")
		_ = logx.RunLogged("systemctl", "stop", "wg-quick@"+core.WGInterface)
		_ = logx.RunLogged("wg-quick", "down", core.WGInterface)
	}
	if err := logx.RunLogged("systemctl", "start", "wg-quick@"+core.WGInterface); err == nil {
		return nil
	}
	return logx.RunLogged("wg-quick", "up", core.WGInterface)
}

// LivePublicKey returns the public key of the running tunnel interface.
func (linuxPlatform) LivePublicKey() (string, error) {
	out, err := exec.Command("wg", "show", core.WGInterface, "public-key").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// hasOurPeer reports whether the live interface carries our Aegis peer.
func (linuxPlatform) hasOurPeer() bool {
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

func (p linuxPlatform) StopTunnel() error {
	if err := logx.RunLogged("systemctl", "stop", "wg-quick@"+core.WGInterface); err != nil {
		_ = logx.RunLogged("wg-quick", "down", core.WGInterface)
	}
	// Never report success with the interface still up: StartTunnel treats
	// an up interface as done, which would leave a stale identity live
	// while install claims the new one.
	if p.TunnelUp() {
		return fmt.Errorf("wg0 is still up after stopping the tunnel")
	}
	return nil
}

func (linuxPlatform) TunnelUp() bool {
	_, err := os.Stat("/sys/class/net/" + core.WGInterface)
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

// pinEndpoint routes the Aegis address via the given gateway so handshakes,
// DoH and the fallback never enter the tunnel. PostUp runs the same command
// at bring-up; RepinEndpoint re-runs it after a roam.
func pinEndpoint(gateway, iface string) error {
	if gateway == "" || iface == "" {
		return fmt.Errorf("no default route to pin %s to", core.AegisIPv4)
	}
	return logx.RunLogged("ip", "route", "replace", core.AegisIPv4, "via", gateway, "dev", iface)
}

func (linuxPlatform) RepinEndpoint(gateway, iface string) error {
	return pinEndpoint(gateway, iface)
}

func (p linuxPlatform) ApplyDNS(iface, gateway string) error {
	// Egress and Tailscale both want to own resolv.conf. Whichever writes last
	// wins, and MagicDNS upstreams are unreachable on filtered networks, so
	// system DNS dies while the egress resolver itself is healthy. Take DNS
	// away from Tailscale before writing the resolved configuration, and keep
	// tailnet names on its local proxy.
	disableTailscaleDNS()
	if !resolvedActive() {
		// No systemd-resolved: resolv.conf is the only resolver state. Skip
		// the drop-in tree entirely so a later-installed resolved does not
		// suddenly honor a stale file, and skip the doomed restart.
		return writeResolvConf()
	}
	if err := os.MkdirAll(linuxResolvedDir, 0755); err != nil {
		return err
	}
	dropIn := "[Resolve]\nDNS=" + core.DoHListenAddr + "\nFallbackDNS=\n"
	if err := os.WriteFile(linuxResolved, []byte(dropIn), 0644); err != nil {
		return err
	}
	if err := logx.RunLogged("systemctl", "restart", "systemd-resolved"); err != nil {
		// No systemd-resolved: point resolv.conf at the listener instead.
		return writeResolvConf()
	}
	_ = logx.RunLogged("resolvectl", "flush-caches")
	// A foreign resolv.conf left from a resolved-less period points at
	// 127.0.0.1:53, which nothing serves (the listener is 127.0.0.1:7103).
	// Applications that read the file directly then fail even though
	// systemd-resolved itself works. Point it at the resolved stub.
	if err := ensureResolvedStub(); err != nil {
		return err
	}
	// The drop-in only fills the global scope. A link that received a
	// resolver over DHCP keeps its own copy in the link scope, and
	// systemd-resolved prefers that scope for names with no routing
	// domain, so the listener is never consulted for most queries. Claim
	// the default-route links explicitly.
	if err := claimDefaultRouteDNS(); err != nil {
		return err
	}
	preserveTailscaleNames()
	return nil
}

// tailscaleDNSEnabled reports whether Tailscale currently owns resolv.conf.
// The CLI is absent on machines without Tailscale, so an error means disabled.
func tailscaleDNSEnabled() bool {
	out, err := exec.Command("tailscale", "dns", "status").Output()
	return err == nil && strings.Contains(string(out), "Tailscale DNS: enabled")
}

// disableTailscaleDNS takes resolv.conf away from Tailscale when it is
// enabled. The marker records that we changed the preference so disable can
// put it back instead of leaving the host changed forever.
func disableTailscaleDNS() {
	if !tailscaleDNSEnabled() {
		return
	}
	if err := logx.RunLogged("tailscale", "set", "--accept-dns=false"); err != nil {
		logx.Logger().Printf("could not take DNS from Tailscale (%v); system DNS may stay on MagicDNS", err)
		return
	}
	if err := os.MkdirAll(core.StateDir(), 0700); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(core.StateDir(), tailscaleDNSMarker), []byte("1\n"), 0644)
	logx.Logger().Printf("disabled Tailscale DNS so egress can own resolv.conf")
}

// restoreTailscaleDNS puts the preference back when this install changed it.
func restoreTailscaleDNS() {
	marker := filepath.Join(core.StateDir(), tailscaleDNSMarker)
	if _, err := os.Stat(marker); err != nil {
		return
	}
	if err := logx.RunLogged("tailscale", "set", "--accept-dns=true"); err != nil {
		return
	}
	_ = os.Remove(marker)
}

// preserveTailscaleNames routes only .ts.net to Tailscale's local DNS proxy,
// which keeps answering tailnet names even with accept-dns off.
func preserveTailscaleNames() {
	if _, err := exec.LookPath("tailscale"); err != nil {
		return
	}
	_ = logx.RunLogged("resolvectl", "dns", "tailscale0", "100.100.100.100")
	_ = logx.RunLogged("resolvectl", "domain", "tailscale0", "~ts.net")
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

// ensureResolvedStub points a foreign /etc/resolv.conf at the systemd-resolved
// stub. It only touches a file that names 127.0.0.1 without the stub address,
// which is what this tool writes when resolved is absent; a resolved-managed
// symlink is left alone.
func ensureResolvedStub() error {
	data, err := os.ReadFile(linuxResolvConf)
	if err != nil {
		return nil
	}
	text := string(data)
	if strings.Contains(text, "127.0.0.53") {
		return nil
	}
	if !resolvConfPointsAtListener(data) {
		return nil
	}
	if err := backupResolvConf(linuxResolvConf, linuxResolvBak); err != nil {
		return err
	}
	const stub = "nameserver 127.0.0.53\noptions edns0 trust-ad\n"
	if fi, lerr := os.Lstat(linuxResolvConf); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(linuxResolvConf)
		return os.Symlink("/run/systemd/resolve/stub-resolv.conf", linuxResolvConf)
	}
	return os.WriteFile(linuxResolvConf, []byte(stub), 0644)
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
	// Tailscale can re-enable MagicDNS after a reboot or a preference change.
	// Take the file back before checking the drop-in, otherwise a healthy
	// egress resolver is bypassed by a resolver the network cannot reach.
	if tailscaleDNSEnabled() {
		return p.ApplyDNS(iface, gateway)
	}
	if !resolvedActive() {
		// Fallback path converges on resolv.conf contents: no rewrite when
		// the listener is already the resolver.
		if data, err := os.ReadFile(linuxResolvConf); err == nil && resolvConfPointsAtListener(data) {
			return nil
		}
		return p.ApplyDNS(iface, gateway)
	}
	data, err := os.ReadFile(linuxResolved)
	if err != nil || !strings.Contains(string(data), core.DoHListenAddr) {
		return p.ApplyDNS(iface, gateway)
	}
	// The drop-in is present, but a reconnect or a DHCP renew can hand a
	// link its own resolver again. Re-claim only the links that lost it,
	// so this stays quiet on the minute-by-minute path.
	if err := ensureResolvedStub(); err != nil {
		return err
	}
	return claimDefaultRouteDNS()
}

// dnsRouteDomain is the systemd-resolved routing domain that makes a link the
// catch-all scope for every name, so all of its queries go to its own server.
const dnsRouteDomain = "~."

// parseDefaultRouteLinks returns the distinct interfaces that carry a default
// route, skipping skip. Pure and unit-tested.
func parseDefaultRouteLinks(output, skip string) []string {
	var links []string
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "dev" {
				continue
			}
			dev := fields[i+1]
			if dev != skip && !seen[dev] {
				seen[dev] = true
				links = append(links, dev)
			}
			break
		}
	}
	return links
}

// linkUsesListener reports whether the resolvectl dns/domain output for one
// link already points at the listener and carries the catch-all routing
// domain. Pure and unit-tested.
func linkUsesListener(dnsOut, domainOut string) bool {
	hasAddr := false
	for _, field := range strings.Fields(dnsOut) {
		if field == core.DoHListenAddr {
			hasAddr = true
			break
		}
	}
	if !hasAddr {
		return false
	}
	for _, field := range strings.Fields(domainOut) {
		if field == dnsRouteDomain {
			return true
		}
	}
	return false
}

// defaultRouteLinks reports the interfaces with a default route. The tunnel
// itself is excluded: it must never supply the resolver that brings it up.
func defaultRouteLinks() []string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil
	}
	return parseDefaultRouteLinks(string(out), core.WGInterface)
}

func linkClaimed(dev string) bool {
	dnsOut, err := exec.Command("resolvectl", "dns", dev).Output()
	if err != nil {
		return false
	}
	domainOut, err := exec.Command("resolvectl", "domain", dev).Output()
	if err != nil {
		return false
	}
	return linkUsesListener(string(dnsOut), string(domainOut))
}

func claimLinkDNS(dev string) error {
	if err := logx.RunLogged("resolvectl", "dns", dev, core.DoHListenAddr); err != nil {
		return fmt.Errorf("resolvectl dns %s: %w", dev, err)
	}
	if err := logx.RunLogged("resolvectl", "domain", dev, dnsRouteDomain); err != nil {
		return fmt.Errorf("resolvectl domain %s: %w", dev, err)
	}
	return nil
}

// claimDefaultRouteDNS points every default-route link at the local listener
// with a catch-all routing domain. Without this the DHCP resolver wins the
// link scope and dnscloak plus DoH are bypassed for most names.
func claimDefaultRouteDNS() error {
	for _, dev := range defaultRouteLinks() {
		if linkClaimed(dev) {
			continue
		}
		if err := claimLinkDNS(dev); err != nil {
			return err
		}
	}
	return nil
}

// releaseDefaultRouteDNS hands each default-route link back to its
// DHCP-provided resolver. Best effort: Disable and Remove must not fail just
// because a link vanished underneath them.
func releaseDefaultRouteDNS() {
	for _, dev := range defaultRouteLinks() {
		_ = logx.RunLogged("resolvectl", "revert", dev)
	}
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
	if err := logx.RunLogged("systemctl", "daemon-reload"); err != nil {
		return err
	}
	return logx.RunLogged("systemctl", "enable", "egress.service")
}

func (linuxPlatform) StartService() error {
	return logx.RunLogged("systemctl", "restart", "egress.service")
}

func (linuxPlatform) StopService() error {
	_ = logx.RunLogged("systemctl", "stop", "egress.service")
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
	if err := logx.RunLogged("systemctl", "enable", "egress.service"); err != nil {
		return err
	}
	return logx.RunLogged("systemctl", "restart", "egress.service")
}

// Disable stops the resolver and the tunnel now, prevents both from starting
// at boot, and puts the system resolver back the way it was. Configs and logs
// stay so Enable is cheap.
func (p linuxPlatform) Disable() error {
	_ = logx.RunLogged("systemctl", "disable", "--now", "egress-update.timer")
	_ = p.StopService()
	_ = logx.RunLogged("systemctl", "disable", "egress.service")

	// The unit is only enabled by Enable or by an older setup, but disabling
	// it here guarantees the tunnel cannot come up on its own after this.
	_ = p.StopTunnel()
	_ = logx.RunLogged("systemctl", "disable", "wg-quick@"+core.WGInterface)

	return p.restoreDNS()
}

// Remove is Disable plus the file system. Everything this tool created goes,
// except a running binary the platform cannot unlink, which is reported.
func (p linuxPlatform) Remove() error {
	_ = p.Disable()
	_ = os.Remove("/etc/systemd/system/egress-update.service")
	_ = os.Remove("/etc/systemd/system/egress-update.timer")
	_ = logx.RunLogged("systemctl", "daemon-reload")

	_ = os.Remove(linuxUnitPath)
	_ = logx.RunLogged("systemctl", "daemon-reload")
	if restored, _ := RestoreBackedConfig(linuxWGPath, linuxWGBak); restored {
		logx.Debugf("restored the pre-existing %s", linuxWGPath)
	} else {
		_ = os.Remove(linuxWGPath)
	}
	_ = os.Remove(linuxResolvBak)

	// Close the debug log before deleting it, or the inode would stay alive
	// until this process exits.
	logx.Close()
	_ = os.Remove(linuxLogPath)
	_ = os.Remove(linuxLogPath + ".old")

	// Only remove the fallback client when this tool put it there: a
	// pre-existing wstunnel that findWstunnel reused is not ours to delete.
	if wstunnel.WstunnelIsOurs(filepath.Join(core.InstallDir(), "wstunnel"), wstunnelLinuxSHA256) {
		_ = os.Remove(filepath.Join(core.InstallDir(), "wstunnel"))
	} else {
		fmt.Printf("leaving %s: not installed by this tool\n", filepath.Join(core.InstallDir(), "wstunnel"))
	}
	RemoveInstalledBinary()
	return nil
}

// restoreDNS removes the local resolver drop-in and restores /etc/resolv.conf
// if this tool had rewritten it.
func (linuxPlatform) restoreDNS() error {
	// Hand the links back to DHCP first, while their current claim still
	// makes sense to revert; otherwise the listener that is about to stop
	// stays the resolver for every name.
	releaseDefaultRouteDNS()
	restoreTailscaleDNS()
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
	if err := logx.RunLogged("systemctl", "restart", "systemd-resolved"); err != nil {
		// No systemd-resolved is the common case there: resolv.conf is
		// the only resolver state, verified below. A present-but-broken
		// unit is a real failure, not an absence.
		if resolvedUnitPresent() {
			return fmt.Errorf("restart systemd-resolved: %w", err)
		}
	} else {
		_ = logx.RunLogged("resolvectl", "flush-caches")
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
	return logx.RunLogged("ping", "-c", "2", "-W", "2", "-i", "0.5", "-n", "-q", host) == nil
}

// The relay leg is in-process on Linux, so there is no external tunneler to
// install or find. These stay for the platform interface and fail honestly if
// anything still asks.
func (linuxPlatform) WstunnelPath() (string, error) {
	return "", errors.New("this platform carries the relay in-process; no external tunneler is used")
}

func (linuxPlatform) InstallWstunnel() (string, error) {
	return "", errors.New("this platform carries the relay in-process; no external tunneler is installed")
}

// SetPeer adds or updates a WireGuard peer at runtime. Linux applies the peer
// and its cryptokey routing directly, so no config rewrite or restart is
// needed the way it is on Windows.
func (linuxPlatform) SetPeer(dev, pubkey, endpoint string, allowed []string) error {
	args := []string{"set", dev, "peer", pubkey}
	if endpoint != "" {
		args = append(args, "endpoint", endpoint, "persistent-keepalive", "25")
	}
	if allowed != nil {
		// Non-nil but empty means clear the routes, which is how a direct link
		// is demoted without losing the peer or its learned endpoint.
		args = append(args, "allowed-ips", strings.Join(allowed, ","))
	}
	out, err := logx.ExecLogged("wg", args...)
	if err != nil {
		return fmt.Errorf("wg set %s peer: %v (%s)", dev, err, logx.Truncate(string(out), 300))
	}
	return nil
}

func (linuxPlatform) RemovePeer(dev, pubkey string) error {
	out, err := logx.ExecLogged("wg", "set", dev, "peer", pubkey, "remove")
	if err != nil {
		return fmt.Errorf("wg set %s peer remove: %v (%s)", dev, err, logx.Truncate(string(out), 300))
	}
	return nil
}

// EnsureRelayPeer exists for the Windows shape of the problem: there the
// service owns its peer list. Here the runtime peer is enough.
func (p linuxPlatform) EnsureRelayPeer(dev, pubkey, endpoint string, allowed []string) (bool, error) {
	return false, p.SetPeer(dev, pubkey, endpoint, allowed)
}

func (linuxPlatform) RemoveRelayPeer(dev, pubkey string) error { return nil }

func Diagnose(w io.Writer) error {
	fmt.Fprintf(w, "  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	section(w, "default route")
	show(w, "ip", "route", "show", "default")

	section(w, "resolver")
	show(w, "resolvectl", "status")

	section(w, "wireguard")
	show(w, "wg", "show", core.WGInterface)

	section(w, "listeners")
	show(w, "sh", "-c", "ss -lunp 2>/dev/null | grep -E ':(7103|7108)' || echo none")

	section(w, "tunnel probe")
	show(w, "ping", "-c", "2", "-W", "2", "-n", core.AegisTunnelIP)

	section(w, "wstunnel")
	show(w, "sh", "-c", "command -v wstunnel || ls -l /usr/local/bin/wstunnel 2>/dev/null || echo not found")

	section(w, "log tail")
	logx.Tail(w, logPath(), 40)
	return nil
}
