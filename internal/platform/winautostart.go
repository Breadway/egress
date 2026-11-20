//go:build windows

package platform

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

// ProxyDir is where the per-user proxy keeps its launcher and state.
func ProxyDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "egress")
	}
	return "."
}

// The Reg* family returns its error code directly and does not set the thread
// last error, so the third return of Call is 0 even on failure. Using it made
// a missing key report "The operation completed successfully.", which named
// neither the key nor the problem.
func RegSetString(subkey, name, value string) error {
	sub, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	var key syscall.Handle
	res, _, _ := procRegOpenKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(sub)),
		0, keySetValue, uintptr(unsafe.Pointer(&key)))
	if res != 0 {
		return syscall.Errno(res)
	}
	defer procRegCloseKey.Call(uintptr(key))
	n, _ := syscall.UTF16PtrFromString(name)
	data, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	res, _, _ = procRegSetValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(n)),
		0, regSZ, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))
	if res != 0 {
		return syscall.Errno(res)
	}
	return nil
}

func RegSetDWORD(subkey, name string, value uint32) error {
	sub, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	var key syscall.Handle
	res, _, _ := procRegOpenKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(sub)),
		0, keySetValue, uintptr(unsafe.Pointer(&key)))
	if res != 0 {
		return syscall.Errno(res)
	}
	defer procRegCloseKey.Call(uintptr(key))
	n, _ := syscall.UTF16PtrFromString(name)
	v := value
	res, _, _ = procRegSetValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(n)),
		0, regDWORD, uintptr(unsafe.Pointer(&v)), 4)
	if res != 0 {
		return syscall.Errno(res)
	}
	return nil
}

func RegDeleteValue(subkey, name string) error {
	sub, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	var key syscall.Handle
	res, _, _ := procRegOpenKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(sub)),
		0, keySetValue, uintptr(unsafe.Pointer(&key)))
	if res != 0 {
		return syscall.Errno(res)
	}
	defer procRegCloseKey.Call(uintptr(key))
	n, _ := syscall.UTF16PtrFromString(name)
	procRegDeleteValueW.Call(uintptr(key), uintptr(unsafe.Pointer(n)))
	return nil
}

// clearUserPAC removes every per-user proxy setting that can keep a browser
// pointed at something that is no longer running: the PAC URL, automatic
// detection, a manual proxy, and the bypass list.
func ClearUserPAC() {
	const key = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	_ = RegDeleteValue(key, "AutoConfigURL")
	_ = RegDeleteValue(key, "AutoDetect")
	_ = RegDeleteValue(key, "ProxyServer")
	_ = RegDeleteValue(key, "ProxyOverride")
	_ = RegSetDWORD(key, "ProxyEnable", 0)
}

// setUserPAC points WinINet at the local PAC file so browsers that follow the
// system proxy use split mode.
func SetUserPAC(url string) error {
	const key = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	if err := RegSetString(key, "AutoConfigURL", url); err != nil {
		return err
	}
	return RegSetDWORD(key, "ProxyEnable", 0)
}

// installProxyAutostart writes a hidden VBS launcher and registers it in the
// per-user Run key. Running the console binary directly from Run would leave a
// console window open for the tray's lifetime.
func InstallProxyAutostart(authPath, relay string) error {
	exe := InstalledBinaryPath()
	dir := ProxyDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	launcher := filepath.Join(dir, "launch-tray.vbs")
	cmdLine := fmt.Sprintf(`"%s" proxy --watchdog --tray --start-relay --relay %s --socks-auth "%s"`, exe, relay, authPath)
	body := "Set sh = CreateObject(\"WScript.Shell\")\r\n" +
		"sh.Run \"" + strings.ReplaceAll(cmdLine, `"`, `""`) + "\", 0, False\r\n"
	if err := os.WriteFile(launcher, []byte(body), 0600); err != nil {
		return err
	}
	runValue := fmt.Sprintf(`wscript.exe //B //Nologo "%s"`, launcher)
	return RegSetString(`Software\Microsoft\Windows\CurrentVersion\Run`, "egress", runValue)
}

// InstallTrayAutostart starts the notification icon at login. It replaces the
// proxy autostart: the tray is the whole per-user process now.
func InstallTrayAutostart(exe string) error {
	dir := ProxyDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	launcher := filepath.Join(dir, "launch-tray.vbs")
	cmdLine := fmt.Sprintf(`"%s" tray`, exe)
	body := "Set sh = CreateObject(\"WScript.Shell\")\r\n" +
		"sh.Run \"" + strings.ReplaceAll(cmdLine, `"`, `""`) + "\", 0, False\r\n"
	if err := os.WriteFile(launcher, []byte(body), 0600); err != nil {
		return err
	}
	return RegSetString(`Software\Microsoft\Windows\CurrentVersion\Run`, "egress",
		fmt.Sprintf(`wscript.exe //B //Nologo "%s"`, launcher))
}

// removeProxyAutostart drops the per-user Run entry and its launcher.
func RemoveProxyAutostart() {
	_ = RegDeleteValue(`Software\Microsoft\Windows\CurrentVersion\Run`, "egress")
	_ = os.Remove(filepath.Join(ProxyDir(), "launch-tray.vbs"))
}

// stopUserProxy ends any per-user proxy or tray this account started, so a
// teardown cannot leave a listener holding the ports a reinstall needs.
func StopUserProxy() {
	_, _ = powershell(`Get-CimInstance Win32_Process -Filter "Name='egress.exe'" -ErrorAction SilentlyContinue | ` +
		`Where-Object { $_.CommandLine -like '* proxy *' } | ` +
		`ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`)
}
