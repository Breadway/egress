//go:build !linux && !windows

package main

import "time"

func installUpdateTimer(time.Duration) error { return nil }
