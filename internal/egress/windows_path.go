//go:build windows

package egress

import (
	sysplatform "egress/internal/platform"
	"fmt"
	"os"
	"path/filepath"
)

// configureWindowsPath puts the install directory on the machine PATH so a new
// shell can run "egress" without a full path. Best effort: a PATH edit is a
// convenience and must never fail an install.
func configureWindowsPath(exe string) {
	dir := filepath.Dir(exe)
	if err := sysplatform.AddToMachinePath(dir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not add %s to PATH: %v\n", dir, err)
		return
	}
	fmt.Printf("added %s to PATH; open a new shell to use it\n", dir)
}

// cleanupWindowsPath removes the entry again. The directory may already be
// gone by the time this runs, which is why it takes no path argument.
func cleanupWindowsPath() {
	if err := sysplatform.RemoveFromMachinePath(filepath.Dir(installedBinaryPath())); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not remove the PATH entry: %v\n", err)
	}
}
