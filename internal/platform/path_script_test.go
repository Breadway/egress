package platform

import (
	"strings"
	"testing"
)

// TestMachinePathScriptAdd pins the shape of the PATH edit: read the value,
// prepend without duplicating, write it back as an expandable string, then
// tell Explorer so new shells see it.
func TestMachinePathScriptAdd(t *testing.T) {
	got := machinePathScript(`C:\ProgramData\egress`, true)

	for _, want := range []string{
		`$dir = 'C:\ProgramData\egress'`,
		`Session Manager\Environment`,
		`$new = @($dir) + @($parts | Where-Object { $_.TrimEnd('\') -ne $dir.TrimEnd('\') })`,
		`Select-Object -Unique`,
		`-Type ExpandString`,
		`SendMessageTimeout`,
		`'Environment'`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("add script missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "refusing to empty") {
		t.Error("add script carries the removal guard")
	}
}

// TestMachinePathScriptRemove proves removal only filters the entry and cannot
// leave the machine PATH empty.
func TestMachinePathScriptRemove(t *testing.T) {
	got := machinePathScript(`C:\ProgramData\egress`, false)
	if !strings.Contains(got, `$new = @($parts | Where-Object { $_.TrimEnd('\') -ne $dir.TrimEnd('\') })`) {
		t.Errorf("remove script does not filter the entry:\n%s", got)
	}
	if !strings.Contains(got, "refusing to empty the machine PATH") {
		t.Errorf("remove script can empty PATH:\n%s", got)
	}
	if strings.Contains(got, "@($dir) + ") {
		t.Errorf("remove script still prepends the entry:\n%s", got)
	}
}
