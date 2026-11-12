//go:build windows

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
	winProgramData = `C:\ProgramData\egress`
	// Backups of pre-existing tunnel configs live beside the install
	// directory, not inside it: remove wipes the directory contents.
	winConfigBakDir = `C:\ProgramData\egress-preinstall-bak`
	winTaskName     = "egress"
	wireGuardMSI    = `wireguard-amd64-1.1.1.msi`

	// SHA-256 is computed from the exact vendor artifacts embedded at build
	// time. The MSI is additionally Authenticode-verified before execution.
	wstunnelWindowsSHA256 = "c7b5b53c1476995310fe10b2f3f6d19006e5a5948984d8d25682b47e8ecb8f73"
	wireGuardMSISHA256    = "7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242"
)

type windowsPlatform struct{}

func newPlatform() platform { return windowsPlatform{} }

func installDir() string { return winProgramData }

// spoolDir holds the pending install report. TempDir is per-user on
// Windows: the elevated installer and the SYSTEM supervisor would use
// different directories and never see each other's reports. The install
// directory is restricted to SYSTEM and Administrators and writable by
// both, so both sides share it.
func spoolDir() string { return winProgramData }

func logPath() string { return filepath.Join(winProgramData, "egress.log") }

func (windowsPlatform) RequirePrivilege() error {
	// "net session" only succeeds with an elevated token.
	if _, err := execLogged("net", "session"); err != nil {
		return errors.New("must run as Administrator")
	}
	return nil
}

func (p windowsPlatform) DefaultRoute() (string, string, error) {
	routes, err := p.DefaultRoutes()
	if err != nil {
		return "", "", err
	}
	return routes[0].Iface, routes[0].Gateway, nil
}

// parseDefaultRoutesWindows parses one "index gateway" pair per line, best
// metric first (the query already sorts). Pure and unit-tested.
func parseDefaultRoutesWindows(out string) []Route {
	var routes []Route
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !digits(fields[0]) {
			continue
		}
		if net.ParseIP(fields[1]) == nil {
			continue
		}
		routes = append(routes, Route{Iface: fields[0], Gateway: fields[1]})
	}
	return routes
}

func (windowsPlatform) DefaultRoutes() ([]Route, error) {
	script := `Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | ForEach-Object { '{0} {1}' -f $_.InterfaceIndex, $_.NextHop }`
	out, err := powershell(script)
	if err != nil {
		return nil, err
	}
	routes := parseDefaultRoutesWindows(out)
	if len(routes) == 0 {
		return nil, errors.New("no default route found")
	}
	return routes, nil
}

func (windowsPlatform) InstallTools() error {
	if wireguardExe() != "" {
		return nil
	}
	if err := extractEmbedded(filepath.Join(winProgramData, wireGuardMSI), embeddedWireGuardMSI, wireGuardMSISHA256); err != nil {
		return fmt.Errorf("extract bundled WireGuard installer: %w", err)
	}
	msi := filepath.Join(winProgramData, wireGuardMSI)
	if err := verifyWireGuardSignature(msi); err != nil {
		return err
	}
	if err := installMSI(msi); err != nil {
		return fmt.Errorf("install bundled WireGuard: %w", err)
	}
	if wireguardExe() == "" {
		return errors.New("bundled WireGuard installer completed but wireguard.exe was not found")
	}
	return nil
}

// installMSI runs the bundled installer silently. 3010 and 1641 mean success
// with a reboot pending or started, which is not a failure here.
func installMSI(path string) error {
	out, err := execLogged("msiexec.exe", "/i", path, "/qn", "/norestart")
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		switch exitErr.ExitCode() {
		case 3010, 1641:
			return nil
		}
	}
	return fmt.Errorf("msiexec: %v (%s)", err, truncate(string(out), 400))
}

// verifyWireGuardSignature uses Windows' Authenticode policy in addition to
// the immutable checksum. It intentionally fails closed if the signer is not
// WireGuard LLC.
func verifyWireGuardSignature(path string) error {
	script := `$s = Get-AuthenticodeSignature -LiteralPath '` + path + `'; ` +
		`if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notlike '*WireGuard LLC*') ` +
		`{ throw ('invalid WireGuard signature: ' + $s.Status + ' / ' + $s.SignerCertificate.Subject) }`
	if _, err := powershell(script); err != nil {
		return fmt.Errorf("bundled WireGuard MSI signature check failed: %w", err)
	}
	return nil
}

func (p windowsPlatform) WriteTunnelConfig(c tunnelConfig) (bool, error) {
	if err := os.MkdirAll(winProgramData, 0700); err != nil {
		return false, err
	}
	if err := os.MkdirAll(winConfigBakDir, 0700); err != nil {
		return false, err
	}

	direct := c
	direct.Endpoint = c.DirectEndpoint()
	relay := c
	relay.Endpoint = c.RelayEndpoint()

	wgConf := filepath.Join(winProgramData, "wg0.conf")
	wsConf := filepath.Join(winProgramData, "wg0ws.conf")
	if err := backupForeignConfig(wgConf, filepath.Join(winConfigBakDir, "wg0.conf")); err != nil {
		return false, err
	}
	if err := backupForeignConfig(wsConf, filepath.Join(winConfigBakDir, "wg0ws.conf")); err != nil {
		return false, err
	}
	changedDirect, err := writeFileChanged(wgConf, []byte(renderWGConfig(direct)))
	if err != nil {
		return false, err
	}
	changedRelay, err := writeFileChanged(wsConf, []byte(renderWGConfig(relay)))
	if err != nil {
		return false, err
	}

	// The directory holds private keys in plain text because the fallback swaps
	// tunnel services at runtime. It always holds the installed binary too,
	// whose embedded key is recoverable with strings. Restrict it in every
	// mode, not just when tunnel configs are written.
	if err := p.SecureInstallDir(); err != nil {
		return false, err
	}
	return changedDirect || changedRelay, nil
}

// installDirACLArgs builds the icacls invocation that locks the install
// directory to SYSTEM and Administrators by SID, so it works on non-English
// installs too. Pure function so the exact SIDs and flags stay testable.
func installDirACLArgs(dir string) []string {
	return []string{
		dir,
		"/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F",
	}
}

// SecureInstallDir applies installDirACLArgs. Unlike most install steps this
// one fails closed: a permissive directory must never pass silently.
func (windowsPlatform) SecureInstallDir() error {
	return runLogged("icacls", installDirACLArgs(winProgramData)...)
}

func (p windowsPlatform) StartTunnel() error {
	if p.TunnelUp() {
		return nil
	}
	return p.swapTo("wg0")
}

func (p windowsPlatform) StopTunnel() error {
	for _, name := range []string{"wg0", "wg0ws"} {
		uninstallTunnel(name)
	}
	if p.TunnelUp() {
		return fmt.Errorf("a tunnel service is still running after stopping the tunnel")
	}
	return nil
}

func (windowsPlatform) TunnelUp() bool {
	return tunnelServiceUp("wg0") || tunnelServiceUp("wg0ws")
}

func (windowsPlatform) TunnelConfigured() bool {
	_, err := os.Stat(filepath.Join(winProgramData, "wg0.conf"))
	return err == nil
}

// LivePublicKey is unimplemented on Windows: the tunnel runs inside the
// WireGuard service, not wireguard-tools, so there is nothing to ask. The
// interface-address check in checkTunnelIdentity still applies, and the
// bounce reinstalls the service from the new config files.
func (windowsPlatform) LivePublicKey() (string, error) { return "", nil }

func (p windowsPlatform) swapTo(name string) error {
	exe := wireguardExe()
	if exe == "" {
		return errors.New("wireguard.exe not found")
	}
	for _, other := range []string{"wg0", "wg0ws"} {
		if other != name {
			uninstallTunnel(other)
		}
	}
	conf := filepath.Join(winProgramData, name+".conf")
	if err := runLogged(exe, "/installtunnelservice", conf); err != nil {
		return err
	}
	return nil
}

// EnsureEndpoint swaps tunnel services, and pins the Aegis address to the
// physical gateway while the relay is in use. Without that pin, wstunnel's own
// connection to Aegis would be routed into the tunnel it is carrying.
func (p windowsPlatform) EnsureEndpoint(endpoint string) error {
	if strings.HasPrefix(endpoint, relayHost+":") {
		if tunnelServiceUp("wg0ws") {
			debugf("endpoint already the relay")
			return nil
		}
		if _, gateway, err := p.DefaultRoute(); err == nil && gateway != "" {
			if err := addHostRoute(gateway); err != nil {
				return err
			}
		}
		debugf("switching tunnel service to the relay")
		return p.swapTo("wg0ws")
	}

	if tunnelServiceUp("wg0") {
		removeHostRoute()
		return nil
	}
	debugf("switching tunnel service to the direct endpoint")
	err := p.swapTo("wg0")
	removeHostRoute()
	return err
}

func addHostRoute(gateway string) error {
	removeHostRoute()
	debugf("pinning %s via %s", aegisIPv4, gateway)
	return runLogged("route", "add", aegisIPv4, "mask", "255.255.255.255", gateway, "metric", "1")
}

func removeHostRoute() {
	_ = runLogged("route", "delete", aegisIPv4)
}

// RepinEndpoint re-points the Aegis address at the new gateway when the relay
// is in use. Without this, a roam strands wstunnel's own connection on the
// old gateway while the default route has moved on.
func (p windowsPlatform) RepinEndpoint(gateway, iface string) error {
	if !tunnelServiceUp("wg0ws") {
		return nil
	}
	if gateway == "" {
		return fmt.Errorf("no default gateway to pin %s to", aegisIPv4)
	}
	return addHostRoute(gateway)
}

func (windowsPlatform) ApplyDNS(iface, gateway string) error {
	if !digits(iface) {
		return fmt.Errorf("unexpected interface identifier %q", iface)
	}
	script := fmt.Sprintf(
		`Set-DnsClientServerAddress -InterfaceIndex %s -ServerAddress '127.0.0.1' -ErrorAction Stop`, iface)
	_, err := powershell(script)
	return err
}

func (windowsPlatform) EnsureDNS(iface, gateway string) error {
	if !digits(iface) {
		return nil
	}
	script := fmt.Sprintf(
		`$s = (Get-DnsClientServerAddress -InterfaceIndex %s -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses; `+
			`if ($s -notcontains '127.0.0.1') { Set-DnsClientServerAddress -InterfaceIndex %s -ServerAddress '127.0.0.1' -ErrorAction SilentlyContinue }`,
		iface, iface)
	_, err := powershell(script)
	return err
}

func (windowsPlatform) InstallService(exePath string, args []string) error {
	debugf("scheduled task command: %s %s", exePath, strings.Join(args, " "))
	script, err := windowsTaskScript(winTaskName, exePath, strings.Join(args, " "), winTriggerStartup, true)
	if err != nil {
		return err
	}
	_, err = powershell(script)
	return err
}

func (windowsPlatform) StartService() error {
	_ = runLogged("schtasks", "/end", "/tn", winTaskName)
	return runLogged("schtasks", "/run", "/tn", winTaskName)
}

func (windowsPlatform) StopService() error {
	_ = runLogged("schtasks", "/end", "/tn", winTaskName)
	// The task may leave its wstunnel child behind, and a running image
	// cannot be replaced during reinstall.
	stopWstunnel()
	return nil
}

// ServiceActive reports whether the scheduled task is currently running. A
// quiet check: verification calls it on every run.
func (windowsPlatform) ServiceActive() bool {
	out, err := exec.Command("schtasks", "/query", "/tn", winTaskName, "/fo", "list").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok &&
			strings.TrimSpace(name) == "Status" {
			return strings.TrimSpace(value) == "Running"
		}
	}
	return false
}

func (windowsPlatform) Enable() error {
	if _, err := execLogged("schtasks", "/query", "/tn", winTaskName); err != nil {
		return errors.New("egress is not installed; run install first")
	}
	if err := runLogged("schtasks", "/change", "/tn", winTaskName, "/enable"); err != nil {
		return err
	}
	_ = runLogged("schtasks", "/end", "/tn", winTaskName)
	return runLogged("schtasks", "/run", "/tn", winTaskName)
}

// Disable stops the resolver and the tunnel now, disables the boot task, and
// puts the adapter back on DHCP-provided DNS. Configs stay so Enable is cheap.
func (p windowsPlatform) Disable() error {
	_ = p.StopService()
	_ = runLogged("schtasks", "/change", "/tn", winTaskName, "/disable")
	_ = runLogged("schtasks", "/delete", "/tn", "egress-update-check", "/f")
	_ = runLogged("schtasks", "/delete", "/tn", "egress-update-apply", "/f")
	removeProxyAutostart()
	clearUserPAC()

	_ = p.StopTunnel()
	stopWstunnel()
	removeHostRoute()
	return p.restoreDNS()
}

// Remove is Disable plus the file system. The install directory is emptied
// except for a running binary, which Windows will not let us unlink.
func (p windowsPlatform) Remove() error {
	_ = p.Disable()
	_ = runLogged("schtasks", "/delete", "/tn", winTaskName, "/f")

	// Decide restores before the wipe and apply them after: the backups
	// live outside the directory precisely so they survive it, and the
	// wipe would destroy anything restored first.
	restored := map[string][]byte{}
	for _, name := range []string{"wg0.conf", "wg0ws.conf"} {
		live := filepath.Join(winProgramData, name)
		bak := filepath.Join(winConfigBakDir, name)
		liveData, liveErr := os.ReadFile(live)
		bakData, bakErr := os.ReadFile(bak)
		if liveErr == nil && bakErr == nil && carriesEgressMarker(liveData) {
			restored[live] = bakData
			_ = os.Remove(bak)
		}
	}

	closeLog()
	removeWindowsDir()
	for live, data := range restored {
		_ = os.MkdirAll(winProgramData, 0700)
		if err := os.WriteFile(live, data, 0600); err == nil {
			debugf("restored the pre-existing %s", filepath.Base(live))
		}
	}
	return nil
}

// restoreDNS resets the adapter that currently carries the default route to
// DHCP/automatic DNS, which is where install changed it.
func (p windowsPlatform) restoreDNS() error {
	iface, _, err := p.DefaultRoute()
	if err != nil {
		return fmt.Errorf("find the default route: %w", err)
	}
	if !digits(iface) {
		return fmt.Errorf("no numeric default-route adapter to reset (got %q)", iface)
	}
	script := fmt.Sprintf(
		`Set-DnsClientServerAddress -InterfaceIndex %s -ResetServerAddresses -ErrorAction Stop`, iface)
	if _, err := powershell(script); err != nil {
		return fmt.Errorf("reset DNS on adapter %s: %w", iface, err)
	}
	// Read back: the adapter must not still point at our listener, or
	// disable would claim success with dead DNS.
	out, err := powershell(`(Get-DnsClientServerAddress -InterfaceIndex ` + iface +
		` -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses`)
	if err != nil {
		return fmt.Errorf("read back DNS on adapter %s: %w", iface, err)
	}
	if dnsServersPointAtListener(out) {
		return fmt.Errorf("adapter %s still points at the egress listener", iface)
	}
	return nil
}

// stopWstunnel terminates only the copy installed in the egress
// directory, so an unrelated wstunnel is left alone.
func stopWstunnel() {
	script := `Get-CimInstance Win32_Process -Filter "Name='wstunnel.exe'" -ErrorAction SilentlyContinue | ` +
		`Where-Object { $_.ExecutablePath -like 'C:\ProgramData\egress\*' } | ` +
		`ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`
	_, _ = powershell(script)
}

// removeWindowsDir deletes the contents of the install directory, skipping the
// running executable if it lives there, then tries to remove the directory.
func removeWindowsDir() {
	self, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}

	var leftover string
	var kept string
	entries, err := os.ReadDir(winProgramData)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(winProgramData, entry.Name())
		if self != "" && filepath.Clean(path) == filepath.Clean(self) {
			leftover = path
			continue
		}
		// A pre-existing fallback client that findWstunnel reused is not
		// ours to delete.
		if strings.EqualFold(entry.Name(), wstunnelExeName()) && !wstunnelIsOurs(path, wstunnelWindowsSHA256) {
			kept = path
			fmt.Printf("leaving %s: not installed by this tool\n", path)
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			fmt.Printf("could not delete %s: %v\n", path, err)
		}
	}

	if leftover == "" && kept == "" {
		if err := os.Remove(winProgramData); err != nil && !os.IsNotExist(err) {
			fmt.Printf("could not delete %s: %v\n", winProgramData, err)
		}
	} else if leftover != "" {
		fmt.Printf("the running binary is %s; delete it after this command exits\n", leftover)
	}
}

func (windowsPlatform) Ping(host string) bool {
	return runLogged("ping", "-n", "2", "-w", "2000", host) == nil
}

func (windowsPlatform) WstunnelPath() (string, error) { return findWstunnel() }

// InstallWstunnel extracts the embedded fallback client. No target-side
// download is attempted: the networks where fallback is needed commonly block
// GitHub before the tunnel has come up.
func (windowsPlatform) InstallWstunnel() (string, error) {
	dest := filepath.Join(winProgramData, wstunnelExeName())
	if err := extractEmbedded(dest, embeddedWstunnel, wstunnelWindowsSHA256); err != nil {
		return "", fmt.Errorf("extract bundled wstunnel: %w", err)
	}
	return dest, nil
}

func wireguardExe() string {
	for _, path := range []string{
		`C:\Program Files\WireGuard\wireguard.exe`,
		`C:\Program Files (x86)\WireGuard\wireguard.exe`,
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	if path, err := exec.LookPath("wireguard.exe"); err == nil {
		return path
	}
	return ""
}

func tunnelServiceUp(name string) bool {
	out, err := execLogged("sc", "query", "WireGuardTunnel$"+name)
	return err == nil && strings.Contains(string(out), "RUNNING")
}

func uninstallTunnel(name string) {
	exe := wireguardExe()
	if exe == "" {
		return
	}
	_ = runLogged(exe, "/uninstalltunnelservice", name)
}

func powershell(script string) (string, error) {
	out, err := execLogged("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return "", fmt.Errorf("powershell: %v (%s)", err, truncate(string(out), 400))
	}
	return strings.TrimSpace(string(out)), nil
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func writeDiagnosePlatform(w io.Writer) error {
	fmt.Fprintf(w, "  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if exe := wireguardExe(); exe != "" {
		fmt.Fprintf(w, "  wireguard.exe: %s\n", exe)
	} else {
		fmt.Fprintf(w, "  wireguard.exe: not found\n")
	}

	section(w, "default route")
	show(w, "powershell", "-NoProfile", "-Command",
		"Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Format-Table InterfaceIndex,NextHop,RouteMetric -AutoSize")

	section(w, "adapter dns")
	show(w, "powershell", "-NoProfile", "-Command",
		"Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceIndex,InterfaceAlias,ServerAddresses -AutoSize")

	section(w, "tunnel services")
	show(w, "sc", "query", "WireGuardTunnel$wg0")
	show(w, "sc", "query", "WireGuardTunnel$wg0ws")

	section(w, "scheduled task")
	show(w, "schtasks", "/query", "/tn", winTaskName, "/v", "/fo", "list")

	section(w, "route for aegis")
	show(w, "route", "print", aegisIPv4)

	section(w, "listeners")
	show(w, "powershell", "-NoProfile", "-Command",
		"Get-NetUDPEndpoint -LocalPort 7103,7108 -ErrorAction SilentlyContinue | Format-Table LocalAddress,LocalPort -AutoSize")
	show(w, "powershell", "-NoProfile", "-Command",
		"Get-NetTCPConnection -LocalPort 7103 -State Listen -ErrorAction SilentlyContinue | Format-Table LocalAddress,LocalPort,State -AutoSize")

	section(w, "wstunnel")
	show(w, "powershell", "-NoProfile", "-Command",
		fmt.Sprintf("$c = Get-Command wstunnel.exe -ErrorAction SilentlyContinue; if ($c) { $c.Source } else { 'not on PATH' }; Get-Item '%s' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName",
			filepath.Join(winProgramData, "wstunnel.exe")))

	section(w, "tunnel probe")
	show(w, "ping", "-n", "2", "-w", "2000", aegisTunnelIP)

	section(w, "files")
	show(w, "powershell", "-NoProfile", "-Command",
		fmt.Sprintf("Get-ChildItem '%s' -ErrorAction SilentlyContinue | Format-Table Name,Length,LastWriteTime -AutoSize", winProgramData))

	section(w, "install directory acl")
	show(w, "icacls", winProgramData)

	section(w, "log tail")
	tailLog(w, 60)
	return nil
}
