//go:build windows

package egress

import (
	"egress/internal/core"
	"egress/internal/split"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// configureWindowsSplit turns a Windows install into split mode: the
// supervisor stays DNS-only, a per-user proxy and tray start at login, and the
// system PAC points at the local proxy.
func configureWindowsSplit() error {
	// An older build may have left a config that claims every destination.
	// Starting that file would take the network away from the machine.
	if c, ok := newPlatform().(interface{ ClampRelayConfig() error }); ok {
		if err := c.ClampRelayConfig(); err != nil {
			return err
		}
	}
	exe, err := installedExePath()
	if err != nil {
		return err
	}
	// The install directory is SYSTEM/Administrators only, and the tray runs
	// with the user's own token, so grant read and execute on what it needs.
	// The directory stays locked; write access is unchanged.
	for _, path := range []string{exe, filepath.Join(filepath.Dir(exe), "wstunnel.exe")} {
		if err := grantUserExecute(path); err != nil {
			return err
		}
	}
	// The proxy, its PAC and its login entry belong to the logged-in user, so
	// they must be applied in that user's session. An update runs install as
	// SYSTEM, and doing it here would write SYSTEM's profile and start a tray
	// in session 0.
	if runningAsSystem() {
		console, err := consoleUser()
		if err != nil {
			return err
		}
		if console == "" {
			fmt.Println("no interactive user is logged on; the proxy and PAC will be applied by the next install")
			return nil
		}
		return runSplitUserTask(console, exe, enrollRelayUser, enrollRelayPass)
	}
	return applyUserSplit(exe, enrollRelayUser, enrollRelayPass)
}

// applyUserSplit writes the per-user proxy settings and starts the tray. It
// must run in the target user's session: the Run key lives in HKCU.
func applyUserSplit(exe, relayUser, relayPass string) error {
	// The proxy is per-user, the install directory is SYSTEM/Administrators
	// only, and ProxyDir is SYSTEM's profile when install runs as SYSTEM. All
	// per-user state therefore lives here, in the user's own profile.
	authPath := filepath.Join(split.ProxyDir(), "socks-auth")
	// An install that enrolled but failed before this step leaves the device
	// credential in the install directory only, and the next `enable` has no
	// token to enrol again. Seed the per-user copy from it so finishing the
	// split setup does not need a new invite.
	if _, _, ok := readAuthFile(authPath); !ok {
		installed := filepath.Join(core.InstallDir(), "socks-auth")
		if u, p, ok := readAuthFile(installed); ok {
			if err := os.MkdirAll(filepath.Dir(authPath), 0700); err == nil {
				if err := writeSocksAuth(authPath, u, p); err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not seed the relay credential: %v\n", err)
				}
			}
		}
	}
	user, pass := relayUser, relayPass
	if user == "" || pass == "" {
		user, pass = resolveSocksAuth(authPath, embeddedSocksUser, embeddedSocksPass)
	}
	if user == "" || pass == "" {
		return fmt.Errorf("this device has no relay credential yet: neither %s nor %s exists. "+
			"Re-run install with a fresh enrollment token, or ask the administrator for the "+
			"device's relay user and password and write \"user:password\" to %s",
			authPath, filepath.Join(core.InstallDir(), "socks-auth"), authPath)
	}
	if err := writeSocksAuth(authPath, user, pass); err != nil {
		return err
	}
	if err := installProxyAutostart(authPath, relayListenAddr); err != nil {
		return err
	}
	pac, err := writePAC()
	if err != nil {
		return err
	}
	// Start the proxy and prove it answers before pointing the browser at it.
	// A PAC that names a dead port is worse than no PAC (EGRESS-98).
	if !split.ProxyListening() {
		cmd := exec.Command(exe, "proxy", "--tray", "--start-relay", "--socks-auth", authPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		if err := cmd.Start(); err != nil {
			return err
		}
		if err := split.WaitForProxy(15 * time.Second); err != nil {
			return err
		}
	}
	return setUserPAC(pacURLForFile(pac))
}

// grantUserExecute lets any interactive account read and run one file. The
// grantee is a SID: a name lookup fails when the account cannot be resolved,
// which is what broke an update that ran install as SYSTEM and asked for
// HOST\SYSTEM (EGRESS-97).
func grantUserExecute(path string) error {
	out, err := exec.Command("icacls", path, "/grant", "*S-1-5-32-545:(RX)").CombinedOutput()
	if err != nil {
		return fmt.Errorf("grant users read on %s: %v: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// splitUserTask is the one-shot task that applies the per-user half of split
// mode inside the logged-in user's session. It exists because an update runs
// install as SYSTEM, where HKCU belongs to SYSTEM and a tray would start in
// session 0.
const splitUserTask = "egress-split-user"

const (
	// proxyListenAddr is the loopback CONNECT proxy the PAC names.
	proxyListenAddr = "127.0.0.1:1081"
	// relayListenAddr is the wstunnel forward the proxy dials for relayed
	// destinations.
	relayListenAddr = "127.0.0.1:1080"
)

// pacFilePath is the PAC next to the installed binary. It is shared by every
// account and readable without elevation, so a browser keeps working when the
// proxy is not running and a SYSTEM check can see it.
func pacFilePath() string {
	// The install directory is SYSTEM/Administrators only, and the browser
	// runs as the user: a PAC there is unreadable and the browser reports
	// itself offline. The PAC belongs in the user's profile (AutoConfigURL is
	// per-user anyway).
	return filepath.Join(split.ProxyDir(), "proxy.pac")
}

// pacURLForFile turns a Windows path into the file:// URL WinINet expects.
func pacURLForFile(path string) string {
	return "file:///" + strings.ReplaceAll(path, `\`, "/")
}

// writePAC writes the PAC into the user's profile, where the browser can read
// it without touching the locked install directory.
func writePAC() (string, error) {
	path := pacFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(split.PacScript(proxyListenAddr)), 0600); err != nil {
		return "", err
	}
	return path, nil
}

// runningAsSystem reports whether this process was started by the task
// scheduler as SYSTEM rather than by a person in an elevated prompt.
func runningAsSystem() bool {
	return strings.EqualFold(os.Getenv("USERNAME"), "SYSTEM")
}

// consoleUser returns the account logged on at the console, or an empty string
// when nobody is. A session-0 process has no other way to name it.
func consoleUser() (string, error) {
	out, err := powershell(`(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName`)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// runSplitUserTask runs the per-user setup in user's session and waits for it.
func runSplitUserTask(user, exe, relayUser, relayPass string) error {
	// Windows paths go inside plain double quotes: %q would double the
	// backslashes and hand the child a path that does not exist.
	args := fmt.Sprintf(`split-user --exe "%s"`, exe)
	if relayUser != "" && relayPass != "" {
		args += fmt.Sprintf(` --relay-user "%s" --relay-pass "%s"`, relayUser, relayPass)
	}
	script, err := windowsTaskScript(splitUserTask, exe, args,
		"New-ScheduledTaskTrigger -Once -At (Get-Date)", userPrincipal(user), false)
	if err != nil {
		return err
	}
	if _, err := powershell(script); err != nil {
		return fmt.Errorf("register per-user setup task: %w", err)
	}
	defer exec.Command("schtasks", "/delete", "/tn", splitUserTask, "/f").Run()

	if out, err := exec.Command("schtasks", "/run", "/tn", splitUserTask).CombinedOutput(); err != nil {
		return fmt.Errorf("run per-user setup task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("schtasks", "/query", "/tn", splitUserTask, "/fo", "list").Output()
		status, result := taskState(string(out))
		if status != "" && !strings.EqualFold(status, "Running") {
			if result != "" && result != "0" {
				return fmt.Errorf("per-user setup task failed with result %s", result)
			}
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("per-user setup task did not finish")
}

// taskState pulls the status and last result out of schtasks list output.
func taskState(out string) (status, result string) {
	for _, line := range strings.Split(out, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(name) {
		case "Status":
			status = strings.TrimSpace(value)
		case "Last Result":
			result = strings.TrimSpace(value)
		}
	}
	return status, result
}

// cmdSplitUser applies the per-user proxy settings and starts the tray. The
// scheduled task calls it inside the user's session.
func cmdSplitUser(args []string) error {
	fs := newFlagSet("split-user")
	exePath := fs.String("exe", "", "installed executable")
	relayUser := fs.String("relay-user", "", "enrolled relay user")
	relayPass := fs.String("relay-pass", "", "enrolled relay password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *exePath == "" {
		return errors.New("missing --exe")
	}
	// The task gives this process no console, so a debug build must log to
	// the shared file for the failure to be visible at all.
	setupLogging(resolveDebug(false))
	if err := applyUserSplit(*exePath, *relayUser, *relayPass); err != nil {
		appLogger().Printf("split-user: %v", err)
		return err
	}
	return nil
}
