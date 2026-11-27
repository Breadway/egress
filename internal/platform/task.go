package platform

import (
	"errors"
	"fmt"
	"strings"
)

// taskStatusFromOutput reads the scheduler's Status line (Ready, Running,
// Disabled) from `schtasks /query /fo list`. It is pure so it can be tested on
// any platform; an absent line returns empty.
func taskStatusFromOutput(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok &&
			strings.TrimSpace(name) == "Status" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// Windows task triggers as PowerShell expressions. Callers pass the whole
// expression so a repeating trigger can carry its own interval.
const (
	TriggerStartup = "New-ScheduledTaskTrigger -AtStartup"
	TriggerLogon   = "New-ScheduledTaskTrigger -AtLogOn"
	TriggerDaily   = "New-ScheduledTaskTrigger -Daily -At 3am"

	SystemPrincipal = "New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest"
)

// TriggerRepeat fires shortly after registration and then every interval.
func TriggerRepeat(intervalMinutes int) string {
	return fmt.Sprintf("New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)"+
		" -RepetitionInterval (New-TimeSpan -Minutes %d)"+
		" -RepetitionDuration (New-TimeSpan -Days 3650)", intervalMinutes)
}

// UserPrincipal runs a task in an interactive user's session.
func UserPrincipal(user string) string {
	return "New-ScheduledTaskPrincipal -UserId " + PSQuote(user) +
		" -LogonType Interactive -RunLevel Limited"
}

// PSQuote wraps a PowerShell single-quoted string.
func PSQuote(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'')
		}
		out = append(out, s[i])
	}
	return string(append(out, '\''))
}

// TaskScript builds the PowerShell that (re)registers a task with explicit
// battery settings: schtasks silently adds "start only on AC power".
func TaskScript(name, exe, args, trigger, principal string, restart bool) (string, error) {
	if trigger == "" || principal == "" {
		return "", errors.New("missing task trigger or principal")
	}
	action := "New-ScheduledTaskAction -Execute " + PSQuote(exe)
	if args != "" {
		action += " -Argument " + PSQuote(args)
	}
	settings := "New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries" +
		" -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew"
	if restart {
		settings += " -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)"
	}
	return "$ErrorActionPreference = 'Stop'\n" +
		"$a = " + action + "\n" +
		"$t = " + trigger + "\n" +
		"$p = " + principal + "\n" +
		"$s = " + settings + "\n" +
		"Register-ScheduledTask -TaskName " + PSQuote(name) +
		" -Action $a -Trigger $t -Principal $p -Settings $s -Force -ErrorAction Stop | Out-Null\n", nil
}
