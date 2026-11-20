//go:build windows

package egress

import (
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

// configureWindowsSplit turns a Windows install into split mode.
//
// Order matters. Retiring the proxy runs first, because a browser left pointed
// at a loopback port this build no longer serves has no internet at all, and
// that must not depend on any later step succeeding. Granting the user execute
// on the binary runs last and is not fatal: without it the tray cannot start,
// which is a cosmetic loss, not a broken install.
func configureWindowsSplit() (err error) {
	// Whatever fails below, the browser must not be left pointed at a proxy
	// that this build stopped running. That is a machine with no internet at
	// all, which is worse than the failure being reported.
	defer func() {
		if err != nil {
			clearUserPAC()
			removeProxyAutostart()
		}
	}()
	// An older config may claim every destination, which takes the LAN away the
	// moment the tunnel starts.
	if c, ok := newPlatform().(interface{ ClampRelayConfig() error }); ok {
		if err := c.ClampRelayConfig(); err != nil {
			return fmt.Errorf("clamp relay config: %w", err)
		}
	}
	exe, ierr := installedExePath()
	if ierr != nil {
		return fmt.Errorf("locate the installed binary: %w", ierr)
	}

	// The per-user task runs the binary with the user's own token, so it must
	// be executable first. A failure here is not fatal: the ACL may already
	// allow it, and the task itself reports what went wrong.
	if err := grantUserExecute(exe); err != nil {
		appLogger().Printf("split: the tray may not start: %v", err)
	}

	if runningAsSystem() {
		console, cerr := consoleUser()
		if cerr != nil {
			return fmt.Errorf("find the console user: %w", cerr)
		}
		if console == "" {
			fmt.Println("no interactive user is logged on; the tray will be started by the next install")
			return nil
		}
		if err := runSplitUserTask(console, exe); err != nil {
			return fmt.Errorf("apply the per-user half for %s: %w", console, err)
		}
	} else if err := applyUserTray(exe); err != nil {
		return err
	}

	return nil
}

// applyUserTray retires the per-user proxy and starts the tray.
//
// The proxy existed to intercept blocked destinations before the tunnel could
// carry them. That decision now lives in the supervisor: learned-blocked
// destinations are routed into WireGuard, so a per-user proxy and PAC only add
// a process, a port, and a thing that can fail. Clear them on upgrade rather
// than leaving a browser pointed at a port nothing serves.
func applyUserTray(exe string) error {
	clearUserPAC()
	removeProxyAutostart()
	stopUserProxy()
	if err := installTrayAutostart(exe); err != nil {
		return fmt.Errorf("start the tray at login: %w", err)
	}
	// Start it now as well. Waiting for the next login makes a working install
	// look broken for the rest of the session.
	if !trayRunning() {
		cmd := exec.Command(exe, "tray")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start the tray: %w", err)
		}
	}
	return nil
}

// trayRunning reports whether a tray process exists for this session.
func trayRunning() bool {
	out, err := powershell(`(Get-CimInstance Win32_Process -Filter "Name='egress.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '* tray*' } | Measure-Object).Count`)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) != "0"
}

// grantUserExecute lets any interactive account read and run one file. The
// grantee is a SID: a name lookup fails when the account cannot be resolved,
// which is what broke an update that ran install as SYSTEM and asked for
// HOST\SYSTEM (EGRESS-97).
func grantUserExecute(path string) error {
	// The file grant is useless without traverse on the directory: Windows
	// checks every component of the path, and the install directory is
	// deliberately closed to anyone but SYSTEM and Administrators.
	if err := grantUsersRX(filepath.Dir(path)); err != nil {
		return err
	}
	return grantUsersRX(path)
}

func grantUsersRX(path string) error {
	out, err := exec.Command("icacls", path, "/grant", "*S-1-5-32-545:(RX)").CombinedOutput()
	if err == nil {
		return nil
	}
	// An ACL written by SYSTEM with no ACE for the installing account refuses
	// WRITE_DAC here. Take ownership and retry before giving up; this is the
	// same repair the start launcher performs when an image will not load.
	if _, terr := exec.Command("takeown", "/f", path).CombinedOutput(); terr == nil {
		if out2, err2 := exec.Command("icacls", path, "/grant", "*S-1-5-32-545:(RX)").CombinedOutput(); err2 == nil {
			return nil
		} else {
			out = append(out, out2...)
		}
	}
	return fmt.Errorf("grant users read on %s: %v: %s", path, err, strings.TrimSpace(string(out)))
}

// splitUserResult is written by the per-user task. The task runs in another
// session, so its exit code is not enough: task state can read Ready with 0
// before it has even started, which used to make the installer return success
// and delete the task before it ran.
const splitUserResult = `C:\Windows\Temp\egress-split-user.txt`

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
	// USERNAME is not reliably "SYSTEM" in a service context: for a machine
	// account it can be the computer name. Ask the token for its SID instead,
	// because everything below turns on knowing whether HKCU is a person's.
	out, err := exec.Command("whoami", "/user").Output()
	return err == nil && strings.Contains(strings.ToUpper(string(out)), "S-1-5-18")
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
func runSplitUserTask(user, exe string) error {
	// Windows paths go inside plain double quotes: %q would double the
	// backslashes and hand the child a path that does not exist.
	args := fmt.Sprintf(`split-user --exe "%s"`, exe)
	script, err := windowsTaskScript(splitUserTask, exe, args,
		"New-ScheduledTaskTrigger -Once -At (Get-Date)", userPrincipal(user), false)
	if err != nil {
		return err
	}
	if _, err := powershell(script); err != nil {
		return fmt.Errorf("register per-user setup task: %w", err)
	}
	defer exec.Command("schtasks", "/delete", "/tn", splitUserTask, "/f").Run()

	_ = os.Remove(splitUserResult)
	if out, err := exec.Command("schtasks", "/run", "/tn", splitUserTask).CombinedOutput(); err != nil {
		return fmt.Errorf("run per-user setup task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(splitUserResult); err == nil {
			text := strings.TrimSpace(string(data))
			if text == "ok" {
				return nil
			}
			if strings.HasPrefix(text, "error: ") {
				return errors.New(strings.TrimPrefix(text, "error: "))
			}
			return fmt.Errorf("per-user setup reported %q", text)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("per-user setup task never reported; no interactive session, or the task did not run")
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

// cmdSplitUser retires the per-user proxy and starts the tray. The scheduled
// task calls it inside the user's session.
func cmdSplitUser(args []string) error {
	fs := newFlagSet("split-user")
	exePath := fs.String("exe", "", "installed executable")
	// Accepted for compatibility with tasks created by older builds.
	_ = fs.String("relay-user", "", "ignored")
	_ = fs.String("relay-pass", "", "ignored")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *exePath == "" {
		return errors.New("missing --exe")
	}
	// The task gives this process no console, so a debug build must log to
	// the shared file for the failure to be visible at all.
	setupLogging(resolveDebug(false))
	err := applyUserTray(*exePath)
	// The installer waits for this file rather than for task state.
	msg := "ok"
	if err != nil {
		appLogger().Printf("split-user: %v", err)
		msg = "error: " + err.Error()
	}
	_ = os.WriteFile(splitUserResult, []byte(msg+"\n"), 0600)
	return err
}
