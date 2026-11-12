//go:build !linux

package main

import "syscall"

// deviceControl is a no-op outside Linux: split mode does not install a default
// route through the tunnel on those platforms, so a normal dial is already
// direct.
func deviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	return nil
}
