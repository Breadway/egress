//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	advapi32            = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW   = advapi32.NewProc("RegOpenKeyExW")
	procRegSetValueExW  = advapi32.NewProc("RegSetValueExW")
	procRegCloseKey     = advapi32.NewProc("RegCloseKey")
	procRegDeleteValueW = advapi32.NewProc("RegDeleteValueW")
)

const (
	hkeyCurrentUser = 0x80000001
	keySetValue     = 0x0002
	regSZ           = 1
	regDWORD        = 4
)

func regSetString(subkey, name, value string) error {
	sub, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	var key syscall.Handle
	res, _, callErr := procRegOpenKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(sub)),
		0, keySetValue, uintptr(unsafe.Pointer(&key)))
	if res != 0 {
		return callErr
	}
	defer procRegCloseKey.Call(uintptr(key))
	n, _ := syscall.UTF16PtrFromString(name)
	data, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	res, _, callErr = procRegSetValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(n)),
		0, regSZ, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))
	if res != 0 {
		return callErr
	}
	return nil
}

func regSetDWORD(subkey, name string, value uint32) error {
	sub, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	var key syscall.Handle
	res, _, callErr := procRegOpenKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(sub)),
		0, keySetValue, uintptr(unsafe.Pointer(&key)))
	if res != 0 {
		return callErr
	}
	defer procRegCloseKey.Call(uintptr(key))
	n, _ := syscall.UTF16PtrFromString(name)
	v := value
	res, _, callErr = procRegSetValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(n)),
		0, regDWORD, uintptr(unsafe.Pointer(&v)), 4)
	if res != 0 {
		return callErr
	}
	return nil
}

func regDeleteValue(subkey, name string) error {
	sub, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	var key syscall.Handle
	res, _, callErr := procRegOpenKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(sub)),
		0, keySetValue, uintptr(unsafe.Pointer(&key)))
	if res != 0 {
		return callErr
	}
	defer procRegCloseKey.Call(uintptr(key))
	n, _ := syscall.UTF16PtrFromString(name)
	procRegDeleteValueW.Call(uintptr(key), uintptr(unsafe.Pointer(n)))
	return nil
}

// clearUserPAC removes the PAC URL and disables the proxy for direct browsing.
func clearUserPAC() {
	const key = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	_ = regDeleteValue(key, "AutoConfigURL")
	_ = regSetDWORD(key, "ProxyEnable", 0)
}

// removeProxyAutostart drops the per-user Run entry and its launcher.
func removeProxyAutostart() {
	_ = regDeleteValue(`Software\Microsoft\Windows\CurrentVersion\Run`, "egress")
	_ = os.Remove(filepath.Join(ProxyDir(), "launch-tray.vbs"))
}

// setUserPAC points WinINet at the local PAC file so browsers that follow the
// system proxy use split mode.
func setUserPAC(url string) error {
	const key = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	if err := regSetString(key, "AutoConfigURL", url); err != nil {
		return err
	}
	return regSetDWORD(key, "ProxyEnable", 0)
}

// installProxyAutostart writes a hidden VBS launcher and registers it in the
// per-user Run key. Running the console binary directly from Run would leave a
// console window open for the tray's lifetime.
func installProxyAutostart(authPath, relay string) error {
	exe, err := installedExePath()
	if err != nil {
		return err
	}
	dir := ProxyDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	launcher := filepath.Join(dir, "launch-tray.vbs")
	cmdLine := fmt.Sprintf(`"%s" proxy --tray --start-relay --relay %s --socks-auth "%s"`, exe, relay, authPath)
	body := "Set sh = CreateObject(\"WScript.Shell\")\r\n" +
		"sh.Run \"" + strings.ReplaceAll(cmdLine, `"`, `""`) + "\", 0, False\r\n"
	if err := os.WriteFile(launcher, []byte(body), 0600); err != nil {
		return err
	}
	runValue := fmt.Sprintf(`wscript.exe //B //Nologo "%s"`, launcher)
	return regSetString(`Software\Microsoft\Windows\CurrentVersion\Run`, "egress", runValue)
}
