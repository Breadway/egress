//go:build !windows

package platform

import "os"

// RemoveStaleFile is only needed where ACLs can strand a file; elsewhere a
// plain remove is enough.
func RemoveStaleFile(path string) { _ = os.Remove(path) }
