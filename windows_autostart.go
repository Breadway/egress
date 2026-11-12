//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW  = advapi32.NewProc("RegOpenKeyExW")
	procRegSetValueExW = advapi32.NewProc("RegSetValueExW")
	procRegCloseKey    = advapi32.NewProc("RegCloseKey")
)

const (
	hkeyCurrentUser = 0x80000001
	keySetValue     = 0x0002
	regSZ           = 1
)

// installProxyAutostart runs the proxy and its tray once per user at login.
// Credentials stay in the auth file, never in the registry value.
func installProxyAutostart(authPath, relay string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	command := fmt.Sprintf(`"%s" proxy --tray --start-relay --relay %s --socks-auth "%s"`, exe, relay, authPath)
	subkey, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Run`)
	if err != nil {
		return err
	}
	var key syscall.Handle
	res, _, callErr := procRegOpenKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(subkey)),
		0, keySetValue, uintptr(unsafe.Pointer(&key)))
	if res != 0 {
		return callErr
	}
	defer procRegCloseKey.Call(uintptr(key))

	name, _ := syscall.UTF16PtrFromString("egress")
	data, err := syscall.UTF16FromString(command)
	if err != nil {
		return err
	}
	res, _, callErr = procRegSetValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(name)),
		0, regSZ, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))
	if res != 0 {
		return callErr
	}
	return nil
}
