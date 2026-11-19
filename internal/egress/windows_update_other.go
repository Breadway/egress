//go:build !windows

package egress

import (
	"errors"

	"egress/internal/update"
)

// stageWindowsRelease is a compile-time counterpart for the windows-only
// staged updater, which applyUpdate calls behind a runtime check.
func stageWindowsRelease(base string, m update.Manifest) error {
	return errors.New("staged updates are Windows only")
}
