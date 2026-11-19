//go:build windows

package egress

// setBootStart enables or disables the boot task and the per-user proxy
// autostart. The current session is left alone.
func setBootStart(enabled bool) error {
	action := "/disable"
	if enabled {
		action = "/enable"
	}
	if err := runLogged("schtasks", "/change", "/tn", winTaskName, action); err != nil {
		return err
	}
	if enabled {
		// Re-register the per-user proxy so it starts again at login.
		if err := configureWindowsSplit(); err != nil {
			return err
		}
		return runLogged("schtasks", "/run", "/tn", winTaskName)
	}
	removeProxyAutostart()
	clearUserPAC()
	return nil
}
