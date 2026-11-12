//go:build !windows

package main

import "errors"

// cmdSplitUser is Windows only: the per-user proxy settings it writes live in
// the Windows registry.
func cmdSplitUser([]string) error {
	return errors.New("split-user is Windows only")
}

// checkWindowsSplit is empty off Windows: there is no split client to probe.
func checkWindowsSplit() string { return "" }
