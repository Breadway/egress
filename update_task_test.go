package main

import (
	"strings"
	"testing"
)

func TestWindowsTaskScriptPowerSettings(t *testing.T) {
	script, err := windowsTaskScript("egress", `C:\ProgramData\egress\egress.exe`, "supervise --debug", winTriggerStartup, true)
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

func TestWindowsTaskScriptOneShotHasNoRestart(t *testing.T) {
	script, err := windowsTaskScript("egress-update-apply", `C:\x.exe`, "update-apply", winTriggerLogon, false)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if strings.Contains(script, "RestartCount") {
		t.Errorf("one-shot task restarts on failure:\n%s", script)
	}
}

func TestWindowsTaskScriptQuoting(t *testing.T) {
	script, err := windowsTaskScript("t", `C:\it's\exe.exe`, `update --staged "C:\a b\egress.exe"`, winTriggerLogon, false)
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

func TestWindowsTaskScriptDailyAndRepeat(t *testing.T) {
	script, err := windowsTaskScript("egress-update-check", `C:\x.exe`, "update --apply", winTriggerDaily, false)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if !strings.Contains(script, "New-ScheduledTaskTrigger -Daily -At 3am") {
		t.Errorf("daily trigger missing:\n%s", script)
	}

	repeat := winTriggerRepeat(30)
	for _, want := range []string{
		"-Once -At (Get-Date).AddMinutes(1)",
		"-RepetitionInterval (New-TimeSpan -Minutes 30)",
		"-RepetitionDuration (New-TimeSpan -Days 3650)",
	} {
		if !strings.Contains(repeat, want) {
			t.Errorf("repeat trigger missing %q: %s", want, repeat)
		}
	}

	if _, err := windowsTaskScript("t", "x", "", "", false); err == nil {
		t.Error("empty trigger accepted")
	}
}

func TestInstalledExePathOnLinux(t *testing.T) {
	path, err := installedExePath()
	if err != nil || path == "" {
		t.Fatalf("path=%q err=%v", path, err)
	}
}
