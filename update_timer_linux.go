//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

const updateServiceUnit = `[Unit]
Description=egress signed update check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/egress update --apply
`

// updateTimerUnit renders the timer. A positive interval polls that often,
// which is what installs use so a published release lands within a minute; a
// zero interval keeps the older daily schedule.
func updateTimerUnit(interval time.Duration) string {
	schedule := "OnCalendar=daily\nRandomizedDelaySec=6h\n"
	if interval > 0 {
		schedule = fmt.Sprintf("OnBootSec=5min\nOnUnitActiveSec=%dm\n", int(interval.Minutes()))
	}
	return `[Unit]
Description=Daily egress signed update check

[Timer]
` + schedule + `Persistent=true

[Install]
WantedBy=timers.target
`
}

// installUpdateTimer enables the signed update check. Failure is reported by
// the caller as a warning, never as an install failure.
func installUpdateTimer(interval time.Duration) error {
	if err := os.WriteFile("/etc/systemd/system/egress-update.service", []byte(updateServiceUnit), 0644); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/systemd/system/egress-update.timer", []byte(updateTimerUnit(interval)), 0644); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	return exec.Command("systemctl", "enable", "--now", "egress-update.timer").Run()
}
