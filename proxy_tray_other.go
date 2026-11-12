//go:build !windows

package main

import (
	"context"
	"errors"
)

func runTray(ctx context.Context, p *splitProxy) error {
	return errors.New("the tray is Windows only; run without --tray")
}

func installProxyAutostart(authPath, relay string) error {
	return errors.New("autostart is Windows only")
}
