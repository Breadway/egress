package platform

import (
	"strings"
	"testing"
)

// TestStartLauncherFailsOpen pins the repair path: probe the image, restore
// the previous build only when it exists, and start regardless.
func TestStartLauncherFailsOpen(t *testing.T) {
	got := startLauncherScript(`C:\ProgramData\egress\egress.exe`, []string{"supervise", "--no-tunnel"})

	for _, want := range []string{
		`set "EXE=C:\ProgramData\egress\egress.exe"`,
		`set "BAK=%EXE%.prev"`,
		`"%EXE%" version >nul 2>&1`,
		`if not errorlevel 1 goto run`,
		`if not exist "%BAK%" goto run`,
		`takeown /f "%EXE%"`,
		`icacls "%EXE%" /reset`,
		`copy /y "%BAK%" "%EXE%"`,
		`:run`,
		`"%EXE%" supervise --no-tunnel`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("launcher missing %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "\n") != strings.Count(got, "\r\n") {
		t.Error("launcher has bare newlines instead of CRLF")
	}
	// The restore must never be the reason the service does not start.
	if strings.Index(got, ":run") > strings.Index(got, `copy /y`) && strings.Contains(got[strings.Index(got, ":run"):], "goto run") {
		t.Error("restore path can loop")
	}
}
