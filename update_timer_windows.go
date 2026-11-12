//go:build windows

package main

// installUpdateTimer creates a daily SYSTEM task that checks for and applies a
// signed release. The task is registered through windowsTaskScript so it still
// runs on battery, and does not inherit the schtasks power defaults.
func installUpdateTimer() error {
	exe, err := installedExePath()
	if err != nil {
		return err
	}
	script, err := windowsTaskScript("egress-update-check", exe, "update --apply", winTriggerDaily)
	if err != nil {
		return err
	}
	_, err = powershell(script)
	return err
}
