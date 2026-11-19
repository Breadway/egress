//go:build !windows

package egress

import "errors"

func cmdDefender([]string) error {
	return errors.New("antivirus exclusions are a Windows feature; nothing to do here")
}

func cleanupDefenderExclusions() {}
