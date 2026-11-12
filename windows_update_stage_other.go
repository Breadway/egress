//go:build !windows

package main

import "errors"

// stageWindowsUpdate lets the shared update client compile off Windows.
// applyUpdate only calls it when the running binary is a Windows build, which
// already rejects non-Windows platforms earlier in the update path.
func stageWindowsUpdate(UpdateManifest, string) error {
	return errors.New("Windows update staging called on another platform")
}
