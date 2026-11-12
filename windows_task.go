package main

import (
	"errors"
	"fmt"
)

// Windows task triggers as PowerShell expressions. Callers pass the whole
// expression so a repeating trigger can carry its own interval.
const (
	winTriggerStartup = "New-ScheduledTaskTrigger -AtStartup"
	winTriggerLogon   = "New-ScheduledTaskTrigger -AtLogOn"
	winTriggerDaily   = "New-ScheduledTaskTrigger -Daily -At 3am"
)

// winTriggerRepeat fires shortly after registration and then every interval.
// Ten years stands in for "indefinitely": Task Scheduler rejects some larger
// duration values, and an unreachable limit is indistinguishable in practice.
func winTriggerRepeat(intervalMinutes int) string {
	return fmt.Sprintf("New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)"+
		" -RepetitionInterval (New-TimeSpan -Minutes %d)"+
		" -RepetitionDuration (New-TimeSpan -Days 3650)", intervalMinutes)
}

// psQuote wraps a PowerShell single-quoted string. Single quotes are literal
// except for an embedded quote, which is escaped by doubling it.
func psQuote(s string) string {
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

// windowsTaskScript builds the PowerShell that (re)registers a SYSTEM task.
//
// Tasks are registered through Register-ScheduledTask rather than schtasks
// because schtasks always writes the default power policy: start only on AC
// power, and stop when the machine switches to battery. The explicit settings
// here also optionally restart the task if it exits unexpectedly, which a
// long-running supervisor wants and a one-shot update check does not.
func windowsTaskScript(name, exe, args, trigger string, restart bool) (string, error) {
	if trigger == "" {
		return "", errors.New("missing task trigger")
	}

	action := "New-ScheduledTaskAction -Execute " + psQuote(exe)
	if args != "" {
		action += " -Argument " + psQuote(args)
	}
	settings := "New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries" +
		" -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew"
	if restart {
		settings += " -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)"
	}

	return "$ErrorActionPreference = 'Stop'\n" +
		"$a = " + action + "\n" +
		"$t = " + trigger + "\n" +
		"$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest\n" +
		"$s = " + settings + "\n" +
		"Register-ScheduledTask -TaskName " + psQuote(name) +
		" -Action $a -Trigger $t -Principal $p -Settings $s -Force -ErrorAction Stop | Out-Null\n", nil
}
