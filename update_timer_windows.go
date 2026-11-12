//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// installUpdateTimer creates a daily SYSTEM task that checks for and applies a
// signed release.
func installUpdateTimer() error {
	exe, err := installedExePath()
	if err != nil {
		return err
	}
	tr := fmt.Sprintf(`"%s" update --apply`, exe)
	out, err := exec.Command("schtasks", "/create", "/tn", "egress-update-check",
		"/tr", tr, "/sc", "daily", "/st", "03:00",
		"/ru", "SYSTEM", "/rl", "HIGHEST", "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("create update task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
