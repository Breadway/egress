//go:build windows

package egress

import (
	"os/exec"
	"strings"
)

// currentSSID asks the WLAN service for the associated network. Empty with no
// error when the machine is not on Wi-Fi, which the allowlist treats as
// "unknown, do not block".
func currentSSID() (string, error) {
	out, err := exec.Command("netsh", "wlan", "show", "interfaces").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) == "SSID" {
			return strings.TrimSpace(value), nil
		}
	}
	return "", nil
}
