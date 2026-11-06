//go:build windows

package main

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
		"/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("installDirACLArgs =\n%q\nwant\n%q", got, want)
	}
}
