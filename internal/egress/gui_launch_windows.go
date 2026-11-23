//go:build windows

package egress

import (
	"os/exec"
	"syscall"
)

// Detach the GUI from the calling console. The app owns its own window and
// tray, so the CLI returns immediately.
func configureGUICommand(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008} // DETACHED_PROCESS
	return nil
}
