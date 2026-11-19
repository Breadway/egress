//go:build windows

package egress

import "syscall"

func hiddenWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
