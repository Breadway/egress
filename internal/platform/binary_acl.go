package platform

import "fmt"

// binaryACLScript re-applies the two grants the install directory uses to one
// file. It is idempotent and exists because a file can land with an empty
// DACL: anything created while the directory is being hardened inherits
// nothing, and the result is a binary that only its owner can touch. An
// administrator then gets "access denied" on a file that is completely intact.
func binaryACLScript(path string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'SilentlyContinue'
icacls '%s' /grant:r '*S-1-5-18:(F)' /grant:r '*S-1-5-32-544:(F)' | Out-Null`, path)
}
