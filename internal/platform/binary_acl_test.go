package platform

import (
	"strings"
	"testing"
)

// TestBinaryACLScript pins the repair: both grants, on the file, by SID.
func TestBinaryACLScript(t *testing.T) {
	got := binaryACLScript(`C:\ProgramData\egress\egress.exe`)
	for _, want := range []string{
		`icacls 'C:\ProgramData\egress\egress.exe'`,
		`/grant:r '*S-1-5-18:(F)'`,
		`/grant:r '*S-1-5-32-544:(F)'`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("script missing %q:\n%s", want, got)
		}
	}
}
