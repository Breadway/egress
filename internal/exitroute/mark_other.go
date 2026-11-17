//go:build !linux

package exitroute

import "syscall"

// markControl is a no-op away from Linux: the learner runs on the exit host,
// which is Linux.
func markControl(int) func(network, address string, c syscall.RawConn) error {
	return nil
}
