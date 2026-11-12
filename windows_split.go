//go:build windows

package main

import (
	"errors"
	"fmt"
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
