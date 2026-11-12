//go:build windows

package main

import "time"

// installUpdateTimer registers the signed update check as a SYSTEM task. A
// zero interval means the daily healthy-install schedule; a positive interval
// makes it poll that often, which a parked install uses to pick up a fix
// without a manual download.
func installUpdateTimer(interval time.Duration) error {
	exe, err := installedExePath()
	if err != nil {
		return err
	}
	trigger := winTriggerDaily
	if interval > 0 {
		trigger = winTriggerRepeat(int(interval.Minutes()))
	}
	script, err := windowsTaskScript("egress-update-check", exe, "update --apply", trigger, false)
	if err != nil {
		return err
	}
	_, err = powershell(script)
	return err
}
