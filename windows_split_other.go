//go:build !windows

package main

import "errors"

func configureWindowsSplit() error {
	return errors.New("windows split is only available on Windows")
}
