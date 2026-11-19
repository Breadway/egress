//go:build !windows

package egress

import "errors"

// The probe exists to validate the Windows split design, where split mode has
// no WireGuard interface today. Linux split already routes through wg0.
func cmdWGProbe([]string) error {
	return errors.New("wg-probe is Windows only")
}
