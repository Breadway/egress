//go:build !windows

package egress

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// configureGUICommand detaches the app from the terminal. The GUI belongs to
// the desktop user, so a root invocation is refused instead of dropping a
// webview into root's session with the wrong HOME and bus.
func configureGUICommand(cmd *exec.Cmd) error {
	if os.Geteuid() == 0 {
		return errors.New("run `egress gui` as your desktop user, not root or sudo")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return nil
}
