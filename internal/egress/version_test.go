package egress

import (
	"runtime"
	"strings"
	"testing"
)

func TestVersionString(t *testing.T) {
	old := buildVersion
	buildVersion = "1.2.3"
	defer func() { buildVersion = old }()

	got := versionString()
	if !strings.HasPrefix(got, "egress 1.2.3 ") {
		t.Fatalf("version string %q does not start with the version", got)
	}
	if !strings.Contains(got, runtime.GOOS+"/"+runtime.GOARCH) {
		t.Fatalf("version string %q omits the platform", got)
	}
}

func TestVersionStringDev(t *testing.T) {
	old := buildVersion
	buildVersion = ""
	defer func() { buildVersion = old }()

	if got := versionString(); !strings.HasPrefix(got, "egress dev ") {
		t.Fatalf("version string %q, want a dev build", got)
	}
}
