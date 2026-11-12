package main

import (
	"strings"
	"testing"
)

func TestWindowsUpdateTaskArgs(t *testing.T) {
	args := windowsUpdateTaskArgs("egress-update", `C:\ProgramData\egress\updates\0.4.0\apply.cmd`)
	joined := strings.Join(args, " ")
	for _, want := range []string{"/create", "/tn egress-update", "/sc onlogon", "/ru SYSTEM", "/rl HIGHEST", "/f"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	if !strings.Contains(joined, `apply.cmd`) {
		t.Errorf("script missing: %q", joined)
	}
}

func TestInstalledExePathOnLinux(t *testing.T) {
	path, err := installedExePath()
	if err != nil || path == "" {
		t.Fatalf("path=%q err=%v", path, err)
	}
}
