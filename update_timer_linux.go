//go:build linux

package main

import (
	"os"
	"os/exec"
)

const updateTimerUnit = `[Unit]
Description=Daily egress signed update check

[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
`

const updateServiceUnit = `[Unit]
Description=egress signed update check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/egress update --apply
`

// installUpdateTimer enables a daily signed update check. Failure is reported
// by the caller as a warning, never as an install failure.
func installUpdateTimer() error {
	if err := os.WriteFile("/etc/systemd/system/egress-update.service", []byte(updateServiceUnit), 0644); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/systemd/system/egress-update.timer", []byte(updateTimerUnit), 0644); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	return exec.Command("systemctl", "enable", "--now", "egress-update.timer").Run()
}
