//go:build !linux && !windows

package egress

import "time"

func installUpdateTimer(time.Duration) error { return nil }
