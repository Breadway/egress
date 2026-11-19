//go:build linux

package egress

import (
	"os/exec"
	"strings"
)

// currentSSID asks the usual Wi-Fi tools. Empty when there is no wireless
// association or no tool installed.
func currentSSID() (string, error) {
	if out, err := exec.Command("iwgetid", "-r").Output(); err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	out, err := exec.Command("nmcli", "-t", "-f", "active,ssid", "dev", "wifi").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		active, ssid, ok := strings.Cut(line, ":")
		if ok && active == "yes" {
			return strings.TrimSpace(ssid), nil
		}
	}
	return "", nil
}
