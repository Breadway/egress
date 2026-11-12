package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestWindowsTaskScriptParses validates the generated PowerShell with the real
// parser when pwsh is available. The scheduled-task scripts are build strings,
// so a syntax mistake would only surface on a Windows machine at install.
func TestWindowsTaskScriptParses(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not installed; skipping PowerShell parse check")
	}
	script, err := TaskScript("egress", `C:\ProgramData\egress\egress.exe`,
		`supervise --no-tunnel --debug`, TriggerStartup, SystemPrincipal, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pwsh); err != nil {
		t.Skip("pwsh path vanished")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "task.ps1")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(pwsh, "-NoProfile", "-Command",
		"$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('"+path+"',[ref]$null,[ref]$e); if($e){$e|ForEach-Object{$_.Message}; exit 1}").CombinedOutput()
	if err != nil {
		t.Fatalf("generated task script does not parse: %v\n%s", err, out)
	}
}
