//go:build windows

package main

import (
	"errors"
	"fmt"
	"net"
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
	exe, err := installedExePath()
	if err != nil {
		return err
	}
	authPath := filepath.Join(ProxyDir(), "socks-auth")
	user, pass := resolveSocksAuth(authPath, embeddedSocksUser, embeddedSocksPass)
	if user == "" || pass == "" {
		return errors.New("no SOCKS relay credentials in this build; rebuild with --socks-user and --socks-pass")
	}
	if err := writeSocksAuth(authPath, user, pass); err != nil {
		return err
	}
	// The PAC is written and made readable here, where the install is
	// elevated. The per-user step only points the browser at it.
	if _, err := writePAC(); err != nil {
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
		return runSplitUserTask(console, exe, authPath)
	}
	return applyUserSplit(exe, authPath)
}

// applyUserSplit writes the per-user proxy settings and starts the tray. It
// must run in the target user's session: the Run key lives in HKCU.
func applyUserSplit(exe, authPath string) error {
	if err := installProxyAutostart(authPath, relayListenAddr); err != nil {
		return err
	}
	// Start the proxy and prove it answers before pointing the browser at it.
	// A PAC that names a dead port is worse than no PAC (EGRESS-98).
	if !proxyListening() {
		cmd := exec.Command(exe, "proxy", "--tray", "--start-relay", "--socks-auth", authPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		if err := cmd.Start(); err != nil {
			return err
		}
		if err := waitForProxy(15 * time.Second); err != nil {
			return err
		}
	}
	return setUserPAC(pacURLForFile(pacFilePath()))
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
	exe, err := installedExePath()
	if err != nil {
		return filepath.Join(ProxyDir(), "proxy.pac")
	}
	return filepath.Join(filepath.Dir(exe), "proxy.pac")
}

// pacURLForFile turns a Windows path into the file:// URL WinINet expects.
func pacURLForFile(path string) string {
	return "file:///" + strings.ReplaceAll(path, `\`, "/")
}

// writePAC writes the PAC beside the installed binary and lets any account
// read it. Requires elevation, so the install does it before dropping to the
// per-user step.
func writePAC() (string, error) {
	path := pacFilePath()
	if err := os.WriteFile(path, []byte(pacScript(proxyListenAddr)), 0644); err != nil {
		return "", err
	}
	out, err := exec.Command("icacls", path, "/grant", "*S-1-5-32-545:(RX)").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("grant users read on %s: %v: %s", path, err, strings.TrimSpace(string(out)))
	}
	return path, nil
}

// proxyListening reports whether the local split proxy accepts connections.
func proxyListening() bool {
	c, err := net.DialTimeout("tcp", proxyListenAddr, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// waitForProxy blocks until the proxy binds its listen address.
func waitForProxy(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if proxyListening() {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("split proxy did not start on %s", proxyListenAddr)
}

// checkWindowsSplit reports the split client's health for install reports and
// verify. An empty string means "not applicable".
func checkWindowsSplit() string {
	if !proxyListening() {
		return "proxy not listening on " + proxyListenAddr
	}
	if _, err := os.Stat(pacFilePath()); err != nil {
		return "PAC missing at " + pacFilePath()
	}
	return "ok"
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
func runSplitUserTask(user, exe, authPath string) error {
	// Windows paths go inside plain double quotes: %q would double the
	// backslashes and hand the child a path that does not exist.
	args := fmt.Sprintf(`split-user --exe "%s" --auth "%s"`, exe, authPath)
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
	authPath := fs.String("auth", "", "SOCKS auth file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *exePath == "" || *authPath == "" {
		return errors.New("missing --exe or --auth")
	}
	// The task gives this process no console, so a debug build must log to
	// the shared file for the failure to be visible at all.
	setupLogging(resolveDebug(false))
	if err := applyUserSplit(*exePath, *authPath); err != nil {
		appLogger().Printf("split-user: %v", err)
		return err
	}
	return nil
}
