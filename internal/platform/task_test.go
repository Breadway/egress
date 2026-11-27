package platform

import (
	"strings"
	"testing"
)

func TestTaskStatusFromOutput(t *testing.T) {
	cases := []struct{ out, want string }{
		{"", ""},
		{"HostName: HAINESY\nTaskName: \\egress\nStatus: Disabled\n", "Disabled"},
		{"TaskName: \\egress\nStatus: Running\n", "Running"},
	}
	for _, tc := range cases {
		if got := taskStatusFromOutput(tc.out); got != tc.want {
			t.Errorf("taskStatusFromOutput(%q) = %q, want %q", tc.out, got, tc.want)
		}
	}
}

func TestWindowsTaskScriptPowerSettings(t *testing.T) {
	script, err := TaskScript("egress", `C:\ProgramData\egress\egress.exe`, "supervise --debug", TriggerStartup, SystemPrincipal, true)
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
	script, err := TaskScript("egress-update-apply", `C:\x.exe`, "update-apply", TriggerLogon, SystemPrincipal, false)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if strings.Contains(script, "RestartCount") {
		t.Errorf("one-shot task restarts on failure:\n%s", script)
	}
}

func TestWindowsTaskScriptQuoting(t *testing.T) {
	script, err := TaskScript("t", `C:\it's\exe.exe`, `update --staged "C:\a b\egress.exe"`, TriggerLogon, SystemPrincipal, false)
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
	script, err := TaskScript("egress-update-check", `C:\x.exe`, "update --apply", TriggerDaily, SystemPrincipal, false)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if !strings.Contains(script, "New-ScheduledTaskTrigger -Daily -At 3am") {
		t.Errorf("daily trigger missing:\n%s", script)
	}

	repeat := TriggerRepeat(30)
	for _, want := range []string{
		"-Once -At (Get-Date).AddMinutes(1)",
		"-RepetitionInterval (New-TimeSpan -Minutes 30)",
		"-RepetitionDuration (New-TimeSpan -Days 3650)",
	} {
		if !strings.Contains(repeat, want) {
			t.Errorf("repeat trigger missing %q: %s", want, repeat)
		}
	}

	if _, err := TaskScript("t", "x", "", "", SystemPrincipal, false); err == nil {
		t.Error("empty trigger accepted")
	}
}

func TestUserPrincipalTaskScript(t *testing.T) {
	args := `split-user --exe "C:\ProgramData\egress\egress.exe" --auth "C:\ProgramData\egress\proxy\socks-auth"`
	script, err := TaskScript("egress-split-user", `C:\ProgramData\egress\egress.exe`, args,
		"New-ScheduledTaskTrigger -Once -At (Get-Date)", UserPrincipal(`DESKTOP-1\ethan`), false)
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
