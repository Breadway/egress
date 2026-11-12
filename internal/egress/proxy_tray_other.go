//go:build !windows

package egress

import (
	"context"
	"egress/internal/split"
	"errors"
)

func runTray(ctx context.Context, p *split.Proxy) error {
	return errors.New("the tray is Windows only; run without --tray")
}

func installProxyAutostart(authPath, relay string) error {
	return errors.New("autostart is Windows only")
}
