//go:build !windows

package egress

import "syscall"

func hiddenWindow() *syscall.SysProcAttr { return nil }
