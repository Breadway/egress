//go:build windows

package platform

import (
	"reflect"
	"testing"
)

// TestInstallDirACLArgs pins the exact icacls invocation: wrong SIDs or flags
// would silently open the credential directory to every local user.
func TestInstallDirACLArgs(t *testing.T) {
	got := installDirACLArgs(`C:\ProgramData\egress`)
	want := []string{
		`C:\ProgramData\egress`,
		"/grant:r", "*S-1-5-18:(OI)(CI)F",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F",
		"/inheritance:r",
		"/remove:g", "*S-1-1-0",
		"/remove:g", "*S-1-5-11",
		"/remove:g", "*S-1-5-32-545",
		"/T", "/C",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("installDirACLArgs =\n%q\nwant\n%q", got, want)
	}
}
