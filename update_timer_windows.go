//go:build windows

package main

import "time"

// installUpdateTimer registers the signed update check as a SYSTEM task. A
// positive interval makes it poll that often; installs use one minute, so a
// published release lands without waiting for the device owner. A zero
// interval keeps the older daily schedule.
func installUpdateTimer(interval time.Duration) error {
	exe, err := installedExePath()
	if err != nil {
		return err
	}
	trigger := winTriggerDaily
	if interval > 0 {
		trigger = winTriggerRepeat(int(interval.Minutes()))
	}
	script, err := windowsTaskScript("egress-update-check", exe, "update --apply", trigger, systemPrincipal, false)
	if err != nil {
		return err
	}
	_, err = powershell(script)
	return err
}
