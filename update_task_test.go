package main

import (
	"strings"
	"testing"
)

func TestWindowsTaskScriptPowerSettings(t *testing.T) {
	script, err := windowsTaskScript("egress", `C:\ProgramData\egress\egress.exe`, "supervise --debug", winTriggerStartup)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	for _, want := range []string{
		"New-ScheduledTaskAction -Execute 'C:\\ProgramData\\egress\\egress.exe' -Argument 'supervise --debug'",
		"New-ScheduledTaskTrigger -AtStartup",
		"-UserId 'SYSTEM'",
		"-RunLevel Highest",
		"-AllowStartIfOnBatteries",
		"-DontStopIfGoingOnBatteries",
		"-StartWhenAvailable",
		"-ExecutionTimeLimit ([TimeSpan]::Zero)",
		"-RestartCount 5",
		"Register-ScheduledTask -TaskName 'egress'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q in:\n%s", want, script)
		}
	}
	if strings.Contains(script, "schtasks") {
		t.Errorf("script still uses schtasks:\n%s", script)
	}
}

func TestWindowsTaskScriptQuoting(t *testing.T) {
	script, err := windowsTaskScript("t", `C:\it's\exe.exe`, `update --staged "C:\a b\egress.exe"`, winTriggerLogon)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if !strings.Contains(script, `'C:\it''s\exe.exe'`) {
		t.Errorf("embedded quote not doubled:\n%s", script)
	}
	if !strings.Contains(script, `'update --staged "C:\a b\egress.exe"'`) {
		t.Errorf("arguments not passed as one quoted string:\n%s", script)
	}
}

func TestWindowsTaskScriptDailyAndUnknown(t *testing.T) {
	script, err := windowsTaskScript("egress-update-check", `C:\x.exe`, "update --apply", winTriggerDaily)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if !strings.Contains(script, "New-ScheduledTaskTrigger -Daily -At 3am") {
		t.Errorf("daily trigger missing:\n%s", script)
	}
	if _, err := windowsTaskScript("t", "x", "", "weekly"); err == nil {
		t.Error("unknown trigger accepted")
	}
}

func TestInstalledExePathOnLinux(t *testing.T) {
	path, err := installedExePath()
	if err != nil || path == "" {
		t.Fatalf("path=%q err=%v", path, err)
	}
}
