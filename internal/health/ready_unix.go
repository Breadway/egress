//go:build !windows

package health

import (
	"errors"
	"os"
	"syscall"
)

// pidAlive reports whether pid exists. Signal 0 performs the existence check
// without touching the target process.
//
// EPERM means the process exists but belongs to another user, which is the
// normal case when an unprivileged `egress verify` checks the root supervisor.
// Treating it as "not running" made a healthy install report a failure.
func pidAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
