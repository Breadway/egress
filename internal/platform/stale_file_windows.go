//go:build windows

package platform

import "os"

// RemoveStaleFile deletes a file left by an earlier failed install, clearing
// its ACL first when needed. A leftover with an empty DACL is writable by
// nobody, so os.Remove fails with access denied even though the directory is
// fine, and the next install cannot rewrite it either.
func RemoveStaleFile(path string) {
	if err := os.Remove(path); err == nil || os.IsNotExist(err) {
		return
	}
	_, _ = powershell("takeown /f '" + path + "' | Out-Null; icacls '" + path + "' /reset | Out-Null")
	_ = os.Remove(path)
}
