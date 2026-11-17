//go:build linux

package exitroute

import (
	"syscall"
)

// markControl tags a probe socket with fwmark so the kernel picks the routing
// table that exits through the path under test.
func markControl(mark int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		}); err != nil {
			return err
		}
		return sockErr
	}
}
