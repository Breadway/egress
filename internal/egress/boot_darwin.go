//go:build darwin

package egress

// setBootStart toggles the launchd daemon without touching the running
// process. `launchctl disable` persists across reboots and survives a plist
// rewrite from an update, which is the behaviour the marker relies on.
func setBootStart(enabled bool) error {
	if enabled {
		_ = runLogged("launchctl", "enable", "system/egress")
		return runLogged("launchctl", "bootstrap", "system", "/Library/LaunchDaemons/egress.plist")
	}
	_ = runLogged("launchctl", "bootout", "system/egress")
	return runLogged("launchctl", "disable", "system/egress")
}
