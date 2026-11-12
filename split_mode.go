package main

import (
	"os"
	"path/filepath"
	"runtime"
)

// splitMarkerPath marks a Linux machine as running split mode. The supervisor
// reads it at startup; install writes or removes it.
func splitMarkerPath() string {
	return filepath.Join(ProfileDir(), "split-mode")
}

// splitEnabled reports whether split mode is configured. Windows split uses
// the proxy path and does not use this marker yet.
func splitEnabled() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := os.Stat(splitMarkerPath())
	return err == nil
}

func setSplitEnabled(on bool) error {
	if !on {
		if err := os.Remove(splitMarkerPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(ProfileDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(splitMarkerPath(), []byte("1\n"), 0600)
}
