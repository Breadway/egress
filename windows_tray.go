//go:build windows

package main

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

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
func runTray(ctx context.Context, p *splitProxy) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	trayPacURL = "http://" + p.listenAddr + "/proxy.pac"
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
