//go:build windows

package egress

import (
	"context"
	"egress/internal/core"
	"egress/internal/split"
	"fmt"
	"os"
	"os/exec"
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

// proxyNetworkAllowed applies the SSID allowlist to the per-user proxy. It
// clears the PAC and returns false when this network is not one the owner
// listed, so the machine browses direct instead of filtering.
func proxyNetworkAllowed() bool {
	dir := split.ProfileDir()
	if len(split.LoadNetworks(dir)) == 0 {
		return true
	}
	ssid, _ := currentSSID()
	if split.NetworkAllowed(dir, ssid) {
		return true
	}
	clearUserPAC()
	appLogger().Printf("proxy: network %q is not in networks.txt; staying direct", ssid)
	return false
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
	procLoadImageW          = user32.NewProc("LoadImageW")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenuW         = user32.NewProc("AppendMenuW")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procShellNotifyIconW    = shell32.NewProc("Shell_NotifyIconW")
	procShellExecuteW       = shell32.NewProc("ShellExecuteW")
	procGetModuleHandleW    = kernel32.NewProc("GetModuleHandleW")
	procMessageBoxW         = user32.NewProc("MessageBoxW")
)

const (
	wmTray      = 0x8000 + 1
	wmUpdate    = 0x8000 + 2
	wmCommand   = 0x0111
	wmRButtonUp = 0x0205
	idiApp      = 32512
	imageIcon   = 1      // LoadImageW resource type
	lrShared    = 0x8000 // LoadImageW: share one handle
	trayIconID  = 1      // icon group id from rsrc_windows_*.syso

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2

	nifMessage = 0x1
	nifIcon    = 0x2
	nifTip     = 0x4

	mfString    = 0x0
	mfGrayed    = 0x1
	mfPopup     = 0x10
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
	trayProxy  *split.Proxy
)

// runTray shows the notification icon, refreshes the two RTTs every five
// seconds, and blocks on the Windows message loop until Exit. It owns the OS
// thread for the lifetime of the loop.
func runTray(ctx context.Context, p *split.Proxy) error {
	runtime.LockOSThread()
	trayProxy = p
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

	// The icon group comes from the resource embedded by rsrc_windows_*.syso.
	// Fall back to the stock application icon if a build was made without one.
	icon, _, _ := procLoadImageW.Call(instance, trayIconID, imageIcon, 0, 0, lrShared)
	if icon == 0 {
		icon, _, _ = procLoadIconW.Call(0, idiApp)
	}
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
				resumeIfExpired()
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
			// Stop the watchdog too, or it restarts the proxy immediately.
			_ = os.WriteFile(filepath.Join(split.ProfileDir(), "proxy-stop"), []byte("1\n"), 0600)
			procPostQuitMessage.Call(0)
		case 3:
			openPath(filepath.Join(egressDataDir(), "egress.log"))
		case 4:
			openPath(egressDataDir())
		case 5:
			if trayProxy != nil {
				trayProxy.ReloadOverrides()
				trayMu.Lock()
				setTipLocked(trayTipLocked())
				trayMu.Unlock()
				nid := trayNID
				procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
			}
		case 6:
			go runDiagnoseWindow()
		case 7:
			runElevated("boot on")
		case 8:
			runElevated("boot off")
		case 9:
			resumeFiltering()
		case 10:
			pauseFiltering(15 * time.Minute)
		case 11:
			go runUpdateCheck()
		case 12:
			openURL("http://" + core.PortalListenAddr + "/")
		default:
			if id := wparam & 0xffff; id >= 100 {
				if spec, ok := trayDomainMenu[id]; ok {
					domain, action, _ := strings.Cut(spec, "|")
					if err := split.AppendOverride(split.ProfileDir(), domain, action == "allow"); err == nil && trayProxy != nil {
						trayProxy.ReloadOverrides()
					}
				}
			}
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
	if blocked, contested, _ := trayProxy.Stats(); blocked > 0 {
		tip += fmt.Sprintf(" | %d blocked", blocked)
		if contested > 0 {
			tip += fmt.Sprintf(" (%d contested)", contested)
		}
	}
	for _, line := range trayPing {
		tip += " | " + line
	}
	return tip
}

// trayStatusLines describes the proxy for the menu's greyed header.
func trayStatusLines(p *split.Proxy) []string {
	blocked, contested, allowed := p.Stats()
	lines := []string{
		"Proxy: listening on " + p.ListenAddr(),
		fmt.Sprintf("Blocked: %d (contested %d), allowed: %d", blocked, contested, allowed),
	}
	if len(split.LoadNetworks(split.ProfileDir())) > 0 {
		ssid, _ := currentSSID()
		state := "not listed"
		if split.NetworkAllowed(split.ProfileDir(), ssid) {
			state = "allowed"
		}
		if ssid == "" {
			ssid = "unknown"
		}
		lines = append(lines, fmt.Sprintf("Network: %s (%s)", ssid, state))
	}
	if bootDisabled() {
		lines = append(lines, "Boot start: off")
	}
	if protos := p.ProtocolStates(); len(protos) > 0 {
		var parts []string
		for _, name := range []string{"udp", "tcp", "dns", "icmp"} {
			if state, ok := protos[name]; ok {
				parts = append(parts, name+"="+state)
			}
		}
		if len(parts) > 0 {
			lines = append(lines, "Network: "+strings.Join(parts, " "))
		}
	}
	return lines
}

// openPath opens a file or folder in the shell.
func openPath(path string) {
	verb, _ := syscall.UTF16PtrFromString("open")
	target, _ := syscall.UTF16PtrFromString(path)
	procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, 1)
}

func egressDataDir() string {
	if dir := os.Getenv("ProgramData"); dir != "" {
		return filepath.Join(dir, "egress")
	}
	return split.ProfileDir()
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

	addGray := func(text string) {
		ptr, _ := syscall.UTF16PtrFromString(text)
		procAppendMenuW.Call(menu, mfString|mfGrayed, 0, uintptr(unsafe.Pointer(ptr)))
	}
	addItem := func(id uintptr, label string) {
		ptr, _ := syscall.UTF16PtrFromString(label)
		procAppendMenuW.Call(menu, mfString, id, uintptr(unsafe.Pointer(ptr)))
	}

	addGray("egress " + reportVersion())
	if trayProxy != nil {
		for _, line := range trayStatusLines(trayProxy) {
			addGray(line)
		}
	}
	trayMu.Lock()
	lines := append([]string(nil), trayPing...)
	trayMu.Unlock()
	for _, line := range lines {
		addGray(line)
	}
	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	addItem(1, "Open PAC")
	addItem(3, "Open log")
	addItem(4, "Open data folder")
	addItem(5, "Reload allow/block lists")
	addItem(6, "Run diagnose")
	addItem(12, "Why is this blocked?")
	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	addItem(7, "Start at boot")
	addItem(8, "Do not start at boot")
	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	if trayProxy != nil {
		if until, paused := pausedUntil(); paused {
			addGray("Filtering paused until " + until.Local().Format("15:04"))
			addItem(9, "Resume filtering")
		} else {
			addItem(10, "Pause filtering for 15 minutes")
		}
		addDomainMenu(menu, trayProxy)
	}
	addItem(11, "Check for updates")
	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	addItem(2, "Exit")

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

// pausePath records a temporary pause so the tray and the proxy agree on it.
func pausePath() string { return filepath.Join(split.ProfileDir(), "paused-until") }

func pausedUntil() (time.Time, bool) {
	data, err := os.ReadFile(pausePath())
	if err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil || time.Now().After(t) {
		return time.Time{}, false
	}
	return t, true
}

func pauseFiltering(d time.Duration) {
	_ = os.MkdirAll(split.ProfileDir(), 0700)
	_ = os.WriteFile(pausePath(), []byte(time.Now().Add(d).UTC().Format(time.RFC3339)+"\n"), 0600)
	clearUserPAC()
}

func resumeFiltering() {
	_ = os.Remove(pausePath())
	_ = setUserPAC(pacURLForFile(pacFilePath()))
}

// resumeIfExpired is called from the refresh tick so a fifteen minute pause
// does not need a reboot to end.
func resumeIfExpired() {
	if _, paused := pausedUntil(); paused {
		return
	}
	if _, err := os.Stat(pausePath()); err == nil {
		_ = os.Remove(pausePath())
		_ = setUserPAC(pacURLForFile(pacFilePath()))
	}
}

// runUpdateCheck runs `egress update --check` and shows the result.
func runUpdateCheck() {
	out, err := exec.Command(os.Args[0], "update", "--check").CombinedOutput()
	text := strings.TrimSpace(string(out))
	if text == "" && err != nil {
		text = err.Error()
	}
	body, _ := syscall.UTF16PtrFromString(truncate(text, 1500))
	caption, _ := syscall.UTF16PtrFromString("egress update")
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(caption)), 0x40)
}

// trayDomainMenu maps dynamic menu ids back to domains.
var trayDomainMenu = map[uintptr]string{}

// addDomainMenu builds a submenu of the worst blocked domains; each opens two
// actions that write the override files. The popup handles are owned by their
// parent menu after MF_POPUP, so they are not destroyed here.
func addDomainMenu(menu uintptr, p *split.Proxy) {
	domains := p.TopDomains(5)
	if len(domains) == 0 {
		return
	}
	parent, _, _ := procCreatePopupMenu.Call()
	if parent == 0 {
		return
	}
	id := uintptr(100)
	for _, domain := range domains {
		sub, _, _ := procCreatePopupMenu.Call()
		if sub == 0 {
			continue
		}
		allow, _ := syscall.UTF16PtrFromString("Allow (direct)")
		block, _ := syscall.UTF16PtrFromString("Keep blocked")
		procAppendMenuW.Call(sub, mfString, id, uintptr(unsafe.Pointer(allow)))
		procAppendMenuW.Call(sub, mfString, id+1, uintptr(unsafe.Pointer(block)))
		trayDomainMenu[id] = domain + "|allow"
		trayDomainMenu[id+1] = domain + "|block"
		label, _ := syscall.UTF16PtrFromString(truncate(domain, 40))
		procAppendMenuW.Call(parent, mfString|mfPopup, sub, uintptr(unsafe.Pointer(label)))
		id += 2
	}
	label, _ := syscall.UTF16PtrFromString("Blocked domains")
	procAppendMenuW.Call(menu, mfString|mfPopup, parent, uintptr(unsafe.Pointer(label)))
}

// runElevated re-runs this binary with the given arguments through the UAC
// prompt. Changing a SYSTEM scheduled task needs that elevation; the tray
// itself runs as the user.
func runElevated(params string) {
	verb, _ := syscall.UTF16PtrFromString("runas")
	exe, err := os.Executable()
	if err != nil {
		return
	}
	target, _ := syscall.UTF16PtrFromString(exe)
	args, _ := syscall.UTF16PtrFromString(params)
	procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)),
		uintptr(unsafe.Pointer(args)), 0, 1)
}

// runDiagnoseWindow runs `egress diagnose` and shows it in a message box. The
// tray is unelevated, so the elevated sections of the output are absent, which
// is exactly what the message box is for: a first look without a console.
func runDiagnoseWindow() {
	out, err := exec.Command(os.Args[0], "diagnose").CombinedOutput()
	text := string(out)
	if err != nil && text == "" {
		text = "diagnose failed: " + err.Error()
	}
	text = truncate(text, 3500)
	body, _ := syscall.UTF16PtrFromString(text)
	caption, _ := syscall.UTF16PtrFromString("egress diagnose")
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(caption)), 0x40)
}
