//go:build windows

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
	"time"
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

func New() Interface { return windowsPlatform{} }

// spoolDir holds the pending install report. TempDir is per-user on
// Windows: the elevated installer and the SYSTEM supervisor would use
// different directories and never see each other's reports. The install
// directory is restricted to SYSTEM and Administrators and writable by
// both, so both sides share it.
func spoolDir() string { return winProgramData }

func logPath() string { return filepath.Join(winProgramData, "egress.log") }

func (windowsPlatform) RequirePrivilege() error {
	// "net session" only succeeds with an elevated token.
	if _, err := logx.ExecLogged("net", "session"); err == nil {
		return nil
	}
	// An unelevated administrator is a right-click away; an account that is
	// not in the Administrators group cannot elevate at all and needs someone
	// else. A filtered token still lists the group, marked deny-only.
	if out, err := logx.ExecLogged("whoami", "/groups"); err == nil &&
		!strings.Contains(string(out), administratorSID) {
		return fmt.Errorf("%s is not an administrator of this PC, and egress has to be installed by one. "+
			"Ask an administrator to run this, or sign in with an administrator account", accountName())
	}
	return errors.New("must run as Administrator: this shell is not elevated, so right-click and choose Run as administrator")
}

// administratorSID is BUILTIN\Administrators, matched by SID so the check
// works on non-English installs.
const administratorSID = "S-1-5-32-544"

// accountName returns DOMAIN\user for messages, falling back to a label that
// never makes the error self-referential.
func accountName() string {
	out, err := logx.ExecLogged("whoami")
	if err != nil {
		return "this account"
	}
	name := strings.TrimSpace(string(out))
	if name == "" {
		return "this account"
	}
	if i := strings.LastIndex(name, `\`); i >= 0 && i+1 < len(name) {
		return name[i+1:] + " (" + name + ")"
	}
	return name
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
	if err := core.ExtractEmbedded(filepath.Join(winProgramData, wireGuardMSI), assets.WireGuardMSI, wireGuardMSISHA256); err != nil {
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
	out, err := logx.ExecLogged("msiexec.exe", "/i", path, "/qn", "/norestart")
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		switch exitErr.ExitCode() {
		case 3010, 1641:
			return nil
		}
	}
	return fmt.Errorf("msiexec: %v (%s)", err, logx.Truncate(string(out), 400))
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

func (p windowsPlatform) WriteTunnelConfig(c core.TunnelConfig) (bool, error) {
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
	if err := BackupForeignConfig(wgConf, filepath.Join(winConfigBakDir, "wg0.conf")); err != nil {
		return false, err
	}
	if err := BackupForeignConfig(wsConf, filepath.Join(winConfigBakDir, "wg0ws.conf")); err != nil {
		return false, err
	}
	changedDirect, err := WriteFileChanged(wgConf, []byte(core.RenderWGConfig(direct)))
	if err != nil {
		return false, err
	}
	changedRelay, err := WriteFileChanged(wsConf, []byte(core.RenderWGConfig(relay)))
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
	// Grants come first on purpose. Between /inheritance:r and the grants the
	// directory has no entries at all, and a file created in that window
	// inherits an empty DACL: only its owner can touch it, so an administrator
	// gets access denied on a binary that is otherwise intact. Explicit grants
	// survive /inheritance:r, so the end state is identical and the window is
	// gone.
	return []string{
		dir,
		"/grant:r", "*S-1-5-18:(OI)(CI)F",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F",
		"/inheritance:r",
		// /inheritance:r drops inherited ACEs but keeps explicit ones. A
		// directory created by the installing user can carry a full-control
		// ACE for that user, and the boot task runs the binary as SYSTEM, so
		// an explicit non-admin grant here is local privilege escalation.
		"/remove:g", "*S-1-1-0", // Everyone
		"/remove:g", "*S-1-5-11", // Authenticated Users
		"/remove:g", "*S-1-5-32-545", // Users
		// /inheritance:r strands files created before the hardening without
		// SYSTEM access, which broke reading the proxy's own state. Apply the
		// grants to the existing tree as well.
		"/T", "/C",
	}
}

// SecureInstallDir applies installDirACLArgs. Unlike most install steps this
// one fails closed: a permissive directory must never pass silently.
func (p windowsPlatform) SecureInstallDir() error {
	if err := logx.RunLogged("icacls", installDirACLArgs(winProgramData)...); err != nil {
		return err
	}
	// Children created by an earlier broken install keep their own empty DACLs,
	// one per file, and each one this install still reads (device.json, the
	// split profile, the relay credential) then fails with access denied. Reset
	// every child to inherit the directory's grants instead of chasing them.
	_ = logx.RunLogged("icacls", winProgramData+`\*`, "/reset", "/T", "/C")
	// The permissive-ACE check below cannot tell a hardened directory from an
	// empty one: an empty DACL has no bad entries and passes, then nothing can
	// be written, which is how an install got as far as "installed to ..." and
	// then failed to write its own launcher. Prove it is usable and rebuild if
	// it is not.
	if err := p.checkInstallDirWritable(); err != nil {
		logx.Logger().Printf("install directory is not writable by this account (%v); rebuilding its ACL", err)
		_ = logx.RunLogged("icacls", winProgramData, "/reset", "/T", "/C")
		if rerr := logx.RunLogged("icacls", installDirACLArgs(winProgramData)...); rerr != nil {
			return fmt.Errorf("rebuild install directory ACL: %w (first failure: %v)", rerr, err)
		}
		if err := p.checkInstallDirWritable(); err != nil {
			return fmt.Errorf("install directory is not writable by this account: %w", err)
		}
	}
	// /inheritance:r keeps explicit ACEs, and both the installing account and
	// any account that touched the directory can carry one. Remove every
	// non-administrator ACE that grants write, then verify. The boot task runs
	// the binary as SYSTEM, so this is a privilege boundary.
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$dir = '%s'
$allowed = @('S-1-5-18', 'S-1-5-32-544')
$write = 'FullControl|Modify|Write|TakeOwnership|ChangePermissions'
for ($pass = 0; $pass -lt 5; $pass++) {
  $bad = Get-Acl $dir | ForEach-Object { $_.Access } | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    ($_.FileSystemRights.ToString() -match $write) -and
    ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -notin $allowed)
  }
  if (-not $bad) { break }
  foreach ($ace in $bad) {
    icacls $dir /remove:g "$($ace.IdentityReference.Value)" | Out-Null
  }
}
$bad = Get-Acl $dir | ForEach-Object { $_.Access } | Where-Object {
  $_.AccessControlType -eq 'Allow' -and
  ($_.FileSystemRights.ToString() -match $write) -and
  ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -notin $allowed)
}
if ($bad) { $bad | ForEach-Object { $_.IdentityReference.Value + ':' + $_.FileSystemRights }; exit 2 } else { 'ok' }`, winProgramData)
	out, err := powershell(script)
	if err != nil {
		return fmt.Errorf("install directory is writable by a non-administrator: %v (%s)", err, logx.Truncate(out, 300))
	}
	return nil
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
	if err := logx.RunLogged(exe, "/installtunnelservice", conf); err != nil {
		return err
	}
	return nil
}

// EnsureEndpoint swaps tunnel services, and pins the Aegis address to the
// physical gateway while the relay is in use. Without that pin, wstunnel's own
// connection to Aegis would be routed into the tunnel it is carrying.
func (p windowsPlatform) EnsureEndpoint(endpoint string) error {
	if strings.HasPrefix(endpoint, core.RelayHost+":") {
		if tunnelServiceUp("wg0ws") {
			logx.Debugf("endpoint already the relay")
			return nil
		}
		if _, gateway, err := p.DefaultRoute(); err == nil && gateway != "" {
			if err := addHostRoute(gateway); err != nil {
				return err
			}
		}
		logx.Debugf("switching tunnel service to the relay")
		return p.swapTo("wg0ws")
	}

	if tunnelServiceUp("wg0") {
		removeHostRoute()
		return nil
	}
	logx.Debugf("switching tunnel service to the direct endpoint")
	err := p.swapTo("wg0")
	removeHostRoute()
	return err
}

func addHostRoute(gateway string) error {
	removeHostRoute()
	logx.Debugf("pinning %s via %s", core.AegisIPv4, gateway)
	return logx.RunLogged("route", "add", core.AegisIPv4, "mask", "255.255.255.255", gateway, "metric", "1")
}

func removeHostRoute() {
	_ = logx.RunLogged("route", "delete", core.AegisIPv4)
}

// RepinEndpoint re-points the Aegis address at the new gateway when the relay
// is in use. Without this, a roam strands wstunnel's own connection on the
// old gateway while the default route has moved on.
func (p windowsPlatform) RepinEndpoint(gateway, iface string) error {
	if !tunnelServiceUp("wg0ws") {
		return nil
	}
	if gateway == "" {
		return fmt.Errorf("no default gateway to pin %s to", core.AegisIPv4)
	}
	return addHostRoute(gateway)
}

func (windowsPlatform) ApplyDNS(iface, gateway string) error {
	if !digits(iface) {
		return fmt.Errorf("unexpected interface identifier %q", iface)
	}
	_, err := powershell(applyDNSScript(iface, winProgramData))
	return err
}

func (p windowsPlatform) EnsureDNS(iface, gateway string) error {
	if !digits(iface) {
		return nil
	}
	script := fmt.Sprintf(
		`$s = (Get-DnsClientServerAddress -InterfaceIndex %s -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses; `+
			`if ($s -contains '127.0.0.1') { 'ok' } else { 'missing' }`, iface)
	out, err := powershell(script)
	if err != nil {
		return err
	}
	// Re-apply through the full path so the DHCP fallback is re-read from the
	// adapter rather than dropped along with the listener entry.
	if strings.Contains(out, "missing") {
		return p.ApplyDNS(iface, gateway)
	}
	return nil
}

func (windowsPlatform) InstallService(exePath string, args []string) error {
	logx.Debugf("scheduled task command: %s %s", exePath, strings.Join(args, " "))
	// Start through a launcher so a binary that Windows refuses to load does
	// not take the service down with it: the launcher proves the image runs
	// and falls back to the previous build before giving up.
	launcher, err := writeStartLauncher(exePath, args)
	if err != nil {
		return err
	}
	script, err := TaskScript(winTaskName, `C:\Windows\System32\cmd.exe`,
		`/c "`+launcher+`"`, TriggerStartup, SystemPrincipal, true)
	if err != nil {
		return err
	}
	_, err = powershell(script)
	return err
}

// writeStartLauncher writes the fail-open start script next to the binary. It
// is a batch file on purpose: a script is not an executable image, so a policy
// that blocks the binary does not block the thing meant to repair it.
func writeStartLauncher(exePath string, args []string) (string, error) {
	dir := filepath.Dir(exePath)
	path := filepath.Join(dir, "start-egress.cmd")
	if err := os.WriteFile(path, []byte(startLauncherScript(exePath, args)), 0755); err != nil {
		return "", fmt.Errorf("write start launcher: %w", err)
	}
	return path, nil
}

func (windowsPlatform) StartService() error {
	_ = logx.RunLogged("schtasks", "/end", "/tn", winTaskName)
	// /end returns before the process exits: the task reports Ready while the
	// old supervisor still holds the DNS port. Starting the new one then
	// fails to bind and exits, which is how an update left the device with no
	// resolver. Wait for the port to be released, then start, and confirm a
	// listener came up.
	waitListenerGone(core.DoHListenAddr, 20*time.Second)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := logx.RunLogged("schtasks", "/run", "/tn", winTaskName); err != nil {
			lastErr = err
		} else if waitListener(core.DoHListenAddr, 20*time.Second) {
			return nil
		}
		_ = logx.RunLogged("schtasks", "/end", "/tn", winTaskName)
		waitListenerGone(core.DoHListenAddr, 5*time.Second)
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("the supervisor task started but nothing is listening on " + core.DoHListenAddr)
}

func (windowsPlatform) StopService() error {
	_ = logx.RunLogged("schtasks", "/end", "/tn", winTaskName)
	waitListenerGone(core.DoHListenAddr, 20*time.Second)
	// The task may leave its wstunnel child behind, and a running image
	// cannot be replaced during reinstall.
	stopWstunnel()
	return nil
}

// waitListener reports whether something answered on addr before the timeout.
func waitListener(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// waitListenerGone blocks until nothing is listening on addr, which is how the
// port tells us the previous supervisor has really exited.
func waitListenerGone(addr string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			return
		}
		conn.Close()
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
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
	if _, err := logx.ExecLogged("schtasks", "/query", "/tn", winTaskName); err != nil {
		return errors.New("egress is not installed; run install first")
	}
	if err := logx.RunLogged("schtasks", "/change", "/tn", winTaskName, "/enable"); err != nil {
		return err
	}
	_ = logx.RunLogged("schtasks", "/end", "/tn", winTaskName)
	return logx.RunLogged("schtasks", "/run", "/tn", winTaskName)
}

// Disable stops the resolver and the tunnel now, disables the boot task, and
// puts the adapter back on DHCP-provided DNS. Configs stay so Enable is cheap.
func (p windowsPlatform) Disable() error {
	_ = p.StopService()
	_ = logx.RunLogged("schtasks", "/change", "/tn", winTaskName, "/disable")
	_ = logx.RunLogged("schtasks", "/delete", "/tn", "egress-update-check", "/f")
	_ = logx.RunLogged("schtasks", "/delete", "/tn", "egress-update-apply", "/f")
	RemoveProxyAutostart()
	ClearUserPAC()
	StopUserProxy()
	// A proxy left in WinHTTP or a stale PAC is enough to look offline even
	// with working DNS. Clear every layer, then flush the resolver cache so
	// answers learned through 127.0.0.1 are not reused.
	_ = logx.RunLogged("netsh", "winhttp", "reset", "proxy")
	_ = logx.RunLogged("ipconfig", "/flushdns")

	_ = p.StopTunnel()
	stopWstunnel()
	removeHostRoute()
	return p.restoreDNS()
}

// Remove is Disable plus the file system. The install directory is emptied
// except for a running binary, which Windows will not let us unlink.
func (p windowsPlatform) Remove() error {
	_ = p.Disable()
	_ = logx.RunLogged("schtasks", "/delete", "/tn", winTaskName, "/f")

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

	logx.Close()
	removeWindowsDir()
	for live, data := range restored {
		_ = os.MkdirAll(winProgramData, 0700)
		if err := os.WriteFile(live, data, 0600); err == nil {
			logx.Debugf("restored the pre-existing %s", filepath.Base(live))
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
		`Set-DnsClientServerAddress -InterfaceIndex %s -ResetServerAddresses -ErrorAction Stop
Remove-Item -LiteralPath '%s' -Force -ErrorAction SilentlyContinue`, iface,
		filepath.Join(winProgramData, "dns-fallback.txt"))
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
	if DNSServersPointAtListener(out) {
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
		if strings.EqualFold(entry.Name(), wstunnel.ExeName()) && !wstunnel.WstunnelIsOurs(path, wstunnelWindowsSHA256) {
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
	return logx.RunLogged("ping", "-n", "2", "-w", "2000", host) == nil
}

func (windowsPlatform) WstunnelPath() (string, error) { return wstunnel.Find() }

// InstallWstunnel extracts the embedded fallback client. No target-side
// download is attempted: the networks where fallback is needed commonly block
// GitHub before the tunnel has come up.
func (windowsPlatform) InstallWstunnel() (string, error) {
	dest := filepath.Join(winProgramData, wstunnel.ExeName())
	// Exclude before writing, not after. The extraction writes a new
	// executable into ProgramData, which is the exact shape Defender reacts
	// to; asking for the exclusion afterwards means the scan can win the race
	// and delete the file we just verified.
	ensureDefenderExclusions(dest)
	if err := core.ExtractEmbedded(dest, assets.Wstunnel, wstunnelWindowsSHA256); err != nil {
		return "", fmt.Errorf("extract bundled wstunnel: %w", err)
	}
	// A scan can still remove it a moment later. One retry after the exclusion
	// is in place, then report honestly instead of claiming the relay works.
	for attempt := 0; attempt < 2; attempt++ {
		if info, err := os.Stat(dest); err == nil && info.Size() > 0 {
			return dest, nil
		}
		if attempt == 0 {
			logx.Logger().Printf("the tunneler disappeared after extraction; retrying with the exclusion in place")
			if err := core.ExtractEmbedded(dest, assets.Wstunnel, wstunnelWindowsSHA256); err != nil {
				return "", fmt.Errorf("extract bundled wstunnel: %w", err)
			}
		}
	}
	if _, err := os.Stat(dest); err != nil {
		return "", fmt.Errorf("the tunneler was removed after extraction (%v); add an exclusion with `egress allow-defender` or install a signed build", err)
	}
	return dest, nil
}

// ensureDefenderExclusions covers the binaries Defender flags and the
// directory they are written in. The directory matters because the extraction
// and update paths write temporary names beside the real ones (wstunnel.exe.new
// is the file a real detection named), and a file-level exclusion does not
// cover those. Best effort, and can be turned off with
// EGRESS_NO_DEFENDER_EXCLUSION=1.
func ensureDefenderExclusions(wstunnelPath string) {
	if strings.TrimSpace(os.Getenv("EGRESS_NO_DEFENDER_EXCLUSION")) != "" {
		return
	}
	paths := []string{filepath.Dir(wstunnelPath), wstunnelPath, InstalledBinaryPath()}
	var quoted []string
	for _, p := range paths {
		quoted = append(quoted, "'"+strings.ReplaceAll(p, "'", "''")+"'")
	}
	script := "$ErrorActionPreference='SilentlyContinue'; " +
		"foreach ($p in @(" + strings.Join(quoted, ",") + ")) { " +
		"if (-not (Get-MpPreference).ExclusionPath -contains $p) { Add-MpPreference -ExclusionPath $p } }"
	if _, err := powershell(script); err != nil {
		logx.Debugf("defender exclusion not applied: %v", err)
		return
	}
	logx.Logger().Printf("defender exclusions set for %s", strings.Join(paths, ", "))
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
	out, err := logx.ExecLogged("sc", "query", "WireGuardTunnel$"+name)
	return err == nil && strings.Contains(string(out), "RUNNING")
}

func uninstallTunnel(name string) {
	exe := wireguardExe()
	if exe == "" {
		return
	}
	_ = logx.RunLogged(exe, "/uninstalltunnelservice", name)
}

func powershell(script string) (string, error) {
	out, err := logx.ExecLogged("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return "", fmt.Errorf("powershell: %v (%s)", err, logx.Truncate(string(out), 400))
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

func Diagnose(w io.Writer) error {
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
	show(w, "route", "print", core.AegisIPv4)

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
	show(w, "ping", "-n", "2", "-w", "2000", core.AegisTunnelIP)

	section(w, "files")
	show(w, "powershell", "-NoProfile", "-Command",
		fmt.Sprintf("Get-ChildItem '%s' -ErrorAction SilentlyContinue | Format-Table Name,Length,LastWriteTime -AutoSize", winProgramData))

	section(w, "install directory acl")
	show(w, "icacls", winProgramData)

	section(w, "installed binary")
	show(w, "powershell", "-NoProfile", "-Command", fmt.Sprintf(
		"$p = '%s'; Get-Item $p -ErrorAction SilentlyContinue | Select-Object Length,LastWriteTime,Attributes | Format-List; "+
			"try { (Get-FileHash $p -Algorithm SHA256).Hash } catch { 'unreadable: ' + $_.Exception.Message }",
		filepath.Join(winProgramData, "egress.exe")))

	section(w, "defender detections")
	show(w, "powershell", "-NoProfile", "-Command",
		"Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -Last 5 InitialDetectionTime,ThreatID,Resources | Format-List")

	section(w, "defender exclusions")
	show(w, "powershell", "-NoProfile", "-Command",
		"(Get-MpPreference).ExclusionPath | Where-Object { $_ -like '*egress*' }")

	section(w, "log tail")
	logx.Tail(w, logPath(), 60)
	return nil
}

// AddToMachinePath puts dir on the machine PATH so a new shell resolves the
// installed binary without a full path. The value is edited in place: entries
// keep their order and %VAR% references survive.
func AddToMachinePath(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("not an absolute directory: %q", dir)
	}
	_, err := powershell(machinePathScript(dir, true))
	return err
}

// RemoveFromMachinePath undoes AddToMachinePath.
func RemoveFromMachinePath(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("not an absolute directory: %q", dir)
	}
	_, err := powershell(machinePathScript(dir, false))
	return err
}

// ensureBinaryACL re-applies the grants the installed binary needs, then reads
// it back. A file that cannot be read after install is the empty-DACL state
// that made administrators see "access denied" on a perfectly good binary.
func ensureBinaryACL(path string) {
	if _, err := powershell(binaryACLScript(path)); err != nil {
		logx.Debugf("binary ACL repair failed: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		logx.Logger().Printf("warning: %s is not readable after install: %v", filepath.Base(path), err)
		return
	}
	_ = f.Close()
}

// checkInstallDirWritable creates and removes one file. Access checks and ACL
// text both lie in the empty-DACL case; a real create is what proves an
// install can proceed.
func (windowsPlatform) checkInstallDirWritable() error {
	f, err := os.CreateTemp(winProgramData, ".acl-check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}
