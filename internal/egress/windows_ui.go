//go:build windows

package egress

import (
	"context"
	"egress/internal/split"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
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

// clearUserPAC removes every per-user proxy setting that can keep a browser
// pointed at something that is no longer running: the PAC URL, automatic
// detection, a manual proxy, and the bypass list.
func clearUserPAC() {
	const key = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	_ = regDeleteValue(key, "AutoConfigURL")
	_ = regDeleteValue(key, "AutoDetect")
	_ = regDeleteValue(key, "ProxyServer")
	_ = regDeleteValue(key, "ProxyOverride")
	_ = regSetDWORD(key, "ProxyEnable", 0)
}

// stopUserProxy ends any per-user proxy or tray this account started, so a
// teardown cannot leave a listener holding the ports a reinstall needs.
func stopUserProxy() {
	_, _ = powershell(`Get-CimInstance Win32_Process -Filter "Name='egress.exe'" -ErrorAction SilentlyContinue | ` +
		`Where-Object { $_.CommandLine -like '* proxy *' } | ` +
		`ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`)
}

// removeProxyAutostart drops the per-user Run entry and its launcher.
func removeProxyAutostart() {
	_ = regDeleteValue(`Software\Microsoft\Windows\CurrentVersion\Run`, "egress")
	_ = os.Remove(filepath.Join(split.ProfileDir(), "launch-tray.vbs"))
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
	dir := split.ProfileDir()
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

var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	shell32                 = syscall.NewLazyDLL("shell32.dll")
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procPostMessageW        = user32.NewProc("PostMessageW")
	procLoadIconW           = user32.NewProc("LoadIconW")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenuW         = user32.NewProc("AppendMenuW")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procShellNotifyIconW    = shell32.NewProc("Shell_NotifyIconW")
	procShellExecuteW       = shell32.NewProc("ShellExecuteW")
	procGetModuleHandleW    = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmTray      = 0x8000 + 1
	wmUpdate    = 0x8000 + 2
	wmCommand   = 0x0111
	wmRButtonUp = 0x0205
	idiApp      = 32512

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2

	nifMessage = 0x1
	nifIcon    = 0x2
	nifTip     = 0x4

	mfString    = 0x0
	mfGrayed    = 0x1
	mfSeparator = 0x800
	tpmRight    = 0x0002
)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type notifyIconData struct {
	Size            uint32
	Wnd             uintptr
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUID            [16]byte
	BalloonIcon     uintptr
}

type winPoint struct {
	X int32
	Y int32
}

type winMsg struct {
	Hwnd     uintptr
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       winPoint
	LPrivate uint32
}

var (
	trayMu     sync.Mutex
	trayHWND   uintptr
	trayNID    notifyIconData
	trayPing   []string
	trayPacURL string
)

// runTray shows the notification icon, refreshes the two RTTs every five
// seconds, and blocks on the Windows message loop until Exit. It owns the OS
// thread for the lifetime of the loop.
func runTray(ctx context.Context, p *split.Proxy) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	trayPacURL = "http://" + p.ListenAddr() + "/proxy.pac"
	trayPing = []string{"1.1.1.1: ...", "example.com: ..."}

	className, err := syscall.UTF16PtrFromString("egressTrayWindow")
	if err != nil {
		return err
	}
	instance, _, _ := procGetModuleHandleW.Call(0)
	class := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:   syscall.NewCallback(trayWndProc),
		Instance:  instance,
		ClassName: className,
	}
	if res, _, callErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&class))); res == 0 {
		return callErr
	}
	// HWND_MESSAGE (-3) is a message-only window: no taskbar button, no focus.
	hwnd, _, callErr := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(className)), 0, 0,
		0, 0, 0, 0, ^uintptr(2), 0, instance, 0)
	if hwnd == 0 {
		return callErr
	}
	trayHWND = hwnd

	icon, _, _ := procLoadIconW.Call(0, idiApp)
	trayMu.Lock()
	trayNID = notifyIconData{
		Wnd:             hwnd,
		ID:              1,
		Flags:           nifMessage | nifIcon | nifTip,
		CallbackMessage: wmTray,
		Icon:            icon,
	}
	setTipLocked("egress: starting")
	trayMu.Unlock()
	trayNID.Size = uint32(unsafe.Sizeof(notifyIconData{}))
	if res, _, nipErr := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&trayNID))); res == 0 {
		return nipErr
	}
	defer procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&trayNID)))

	go func() {
		refresh := time.NewTicker(5 * time.Second)
		defer refresh.Stop()
		refreshPings()
		procPostMessageW.Call(hwnd, wmUpdate, 0, 0)
		for {
			select {
			case <-ctx.Done():
				procPostMessageW.Call(hwnd, wmCommand, 2, 0)
				return
			case <-refresh.C:
				refreshPings()
				procPostMessageW.Call(hwnd, wmUpdate, 0, 0)
			}
		}
	}()

	var m winMsg
	for {
		got, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(got) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	return nil
}

func trayWndProc(hwnd, message, wparam, lparam uintptr) uintptr {
	switch message {
	case wmTray:
		if lparam == wmRButtonUp || lparam == 0x0202 { // right or left click
			showTrayMenu(hwnd)
		}
		return 0
	case wmUpdate:
		trayMu.Lock()
		setTipLocked(trayTipLocked())
		trayMu.Unlock()
		nid := trayNID
		procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
		return 0
	case wmCommand:
		switch wparam & 0xffff {
		case 1:
			openURL(trayPacURL)
		case 2:
			procPostQuitMessage.Call(0)
		}
		return 0
	}
	res, _, _ := procDefWindowProcW.Call(hwnd, message, wparam, lparam)
	return res
}

func refreshPings() {
	lines := make([]string, 0, 2)
	for _, target := range []string{"1.1.1.1", "example.com"} {
		rtt, err := pingHost(target, 1500*time.Millisecond)
		if err != nil {
			lines = append(lines, target+": no reply")
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: %d ms", target, rtt.Milliseconds()))
	}
	trayMu.Lock()
	trayPing = lines
	trayMu.Unlock()
}

func trayTipLocked() string {
	tip := "egress"
	for _, line := range trayPing {
		tip += " | " + line
	}
	return tip
}

func setTipLocked(text string) {
	for i := range trayNID.Tip {
		trayNID.Tip[i] = 0
	}
	words := syscall.StringToUTF16(text)
	copy(trayNID.Tip[:len(trayNID.Tip)-1], words)
}

func showTrayMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	trayMu.Lock()
	lines := append([]string(nil), trayPing...)
	trayMu.Unlock()
	for _, line := range lines {
		text, _ := syscall.UTF16PtrFromString(line)
		procAppendMenuW.Call(menu, mfString|mfGrayed, 0, uintptr(unsafe.Pointer(text)))
	}
	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	open, _ := syscall.UTF16PtrFromString("Open PAC")
	procAppendMenuW.Call(menu, mfString, 1, uintptr(unsafe.Pointer(open)))
	exit, _ := syscall.UTF16PtrFromString("Exit")
	procAppendMenuW.Call(menu, mfString, 2, uintptr(unsafe.Pointer(exit)))

	var pt winPoint
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(hwnd)
	procTrackPopupMenu.Call(menu, tpmRight, uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)
}

func openURL(url string) {
	verb, _ := syscall.UTF16PtrFromString("open")
	target, _ := syscall.UTF16PtrFromString(url)
	procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, 1)
}
