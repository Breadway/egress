//go:build windows

package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"syscall"
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
	if err := installProxyAutostart(authPath, "127.0.0.1:1080"); err != nil {
		return err
	}
	if err := setUserPAC("http://127.0.0.1:1081/proxy.pac"); err != nil {
		return err
	}
	// Start it now without flashing a console window.
	cmd := exec.Command(exe, "proxy", "--tray", "--start-relay", "--socks-auth", authPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd.Start()
}
