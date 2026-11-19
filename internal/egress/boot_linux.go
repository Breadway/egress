//go:build linux

package egress

import "fmt"

// setBootStart toggles the boot unit. The update timer stays enabled.
func setBootStart(enabled bool) error {
	action := "disable"
	if enabled {
		action = "enable"
	}
	if err := runLogged("systemctl", action, "egress.service"); err != nil {
		return err
	}
	if enabled {
		return runLogged("systemctl", "start", "egress.service")
	}
	fmt.Println("the running supervisor keeps running; `egress disable` stops it now")
	return nil
}
