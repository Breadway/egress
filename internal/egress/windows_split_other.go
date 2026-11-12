//go:build !windows

package egress

import "errors"

func configureWindowsSplit() error {
	return errors.New("windows split is only available on Windows")
}
