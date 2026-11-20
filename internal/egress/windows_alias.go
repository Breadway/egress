//go:build windows

package egress

import sysplatform "egress/internal/platform"

// Task and per-user Windows helpers live in internal/platform. These aliases
// keep this package's Windows call sites unchanged.
const (
	winTaskName    = "egress"
	winProgramData = `C:\ProgramData\egress`

	winTriggerStartup = sysplatform.TriggerStartup
	winTriggerLogon   = sysplatform.TriggerLogon
	winTriggerDaily   = sysplatform.TriggerDaily
	systemPrincipal   = sysplatform.SystemPrincipal
)

func windowsTaskScript(name, exe, args, trigger, principal string, restart bool) (string, error) {
	return sysplatform.TaskScript(name, exe, args, trigger, principal, restart)
}

func userPrincipal(user string) string { return sysplatform.UserPrincipal(user) }

func clearUserPAC()               { sysplatform.ClearUserPAC() }
func setUserPAC(url string) error { return sysplatform.SetUserPAC(url) }

func installTrayAutostart(exe string) error { return sysplatform.InstallTrayAutostart(exe) }

func installProxyAutostart(authPath, relay string) error {
	return sysplatform.InstallProxyAutostart(authPath, relay)
}

func removeProxyAutostart() { sysplatform.RemoveProxyAutostart() }
func stopUserProxy()        { sysplatform.StopUserProxy() }

func winTriggerRepeat(minutes int) string { return sysplatform.TriggerRepeat(minutes) }

func powershell(script string) (string, error) { return sysplatform.PowerShell(script) }
