package main

import "fmt"

// Windows task trigger names understood by windowsTaskScript.
const (
	winTriggerStartup = "startup"
	winTriggerDaily   = "daily"
	winTriggerLogon   = "logon"
)

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
// power, and stop when the machine switches to battery. On a laptop that kills
// the supervisor seconds after install, which then looks like a dead process
// to verification and triggers a full rollback (EGRESS-91). The explicit
// settings here also restart the task if it does exit unexpectedly, so a
// transient crash no longer leaves the machine without DNS.
func windowsTaskScript(name, exe, args, trigger string) (string, error) {
	var trig string
	switch trigger {
	case winTriggerStartup:
		trig = "New-ScheduledTaskTrigger -AtStartup"
	case winTriggerDaily:
		trig = "New-ScheduledTaskTrigger -Daily -At 3am"
	case winTriggerLogon:
		trig = "New-ScheduledTaskTrigger -AtLogOn"
	default:
		return "", fmt.Errorf("unknown task trigger %q", trigger)
	}

	action := "New-ScheduledTaskAction -Execute " + psQuote(exe)
	if args != "" {
		action += " -Argument " + psQuote(args)
	}

	return "$ErrorActionPreference = 'Stop'\n" +
		"$a = " + action + "\n" +
		"$t = " + trig + "\n" +
		"$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest\n" +
		"$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries" +
		" -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew" +
		" -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)\n" +
		"Register-ScheduledTask -TaskName " + psQuote(name) +
		" -Action $a -Trigger $t -Principal $p -Settings $s -Force -ErrorAction Stop | Out-Null\n", nil
}
