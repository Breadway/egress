package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestWindowsTaskScriptPowerSettings(t *testing.T) {
	script, err := windowsTaskScript("egress", `C:\ProgramData\egress\egress.exe`, "supervise --debug", winTriggerStartup, systemPrincipal, true)
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
	script, err := windowsTaskScript("egress-update-apply", `C:\x.exe`, "update-apply", winTriggerLogon, systemPrincipal, false)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if strings.Contains(script, "RestartCount") {
		t.Errorf("one-shot task restarts on failure:\n%s", script)
	}
}

func TestWindowsTaskScriptQuoting(t *testing.T) {
	script, err := windowsTaskScript("t", `C:\it's\exe.exe`, `update --staged "C:\a b\egress.exe"`, winTriggerLogon, systemPrincipal, false)
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
	script, err := windowsTaskScript("egress-update-check", `C:\x.exe`, "update --apply", winTriggerDaily, systemPrincipal, false)
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

	if _, err := windowsTaskScript("t", "x", "", "", systemPrincipal, false); err == nil {
		t.Error("empty trigger accepted")
	}
}

func TestUserPrincipalTaskScript(t *testing.T) {
	args := `split-user --exe "C:\ProgramData\egress\egress.exe" --auth "C:\ProgramData\egress\proxy\socks-auth"`
	script, err := windowsTaskScript("egress-split-user", `C:\ProgramData\egress\egress.exe`, args,
		"New-ScheduledTaskTrigger -Once -At (Get-Date)", userPrincipal(`DESKTOP-1\ethan`), false)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	for _, want := range []string{
		"New-ScheduledTaskPrincipal -UserId 'DESKTOP-1\\ethan'",
		"-LogonType Interactive",
		"-RunLevel Limited",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q in:\n%s", want, script)
		}
	}
	if strings.Contains(script, "ServiceAccount") {
		t.Errorf("per-user task runs as SYSTEM:\n%s", script)
	}
}

func TestBuildReportParkedIsFailed(t *testing.T) {
	results := checkResults{Tunnel: "skipped", Probe: "skipped"}
	data, err := buildReport(tunnelConfig{}, results, errors.New("split client setup failed"), true)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "failed" {
		t.Errorf("status = %v, want failed (a parked install is not healthy)", got["status"])
	}
	if got["parked"] != true {
		t.Errorf("parked = %v, want true", got["parked"])
	}

	ok, err := buildReport(tunnelConfig{}, results, nil, false)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	got = map[string]any{}
	if err := json.Unmarshal(ok, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] == "failed" {
		t.Errorf("clean install reported failed: %v", got["status"])
	}
	if _, present := got["parked"]; present {
		t.Errorf("clean install reported parked")
	}
}

func TestInstalledExePathOnLinux(t *testing.T) {
	path, err := installedExePath()
	if err != nil || path == "" {
		t.Fatalf("path=%q err=%v", path, err)
	}
}
