//go:build !windows

package health

import (
	"os"
	"syscall"
)

// pidAlive reports whether pid exists. Signal 0 performs the existence check
// without touching the target process.
func pidAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
