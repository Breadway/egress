//go:build darwin

package egress

import (
	"os/exec"
	"strings"
)

// currentSSID uses networksetup; the output is "Current Wi-Fi Network: Name".
func currentSSID() (string, error) {
	out, err := exec.Command("networksetup", "-getairportnetwork", "en0").Output()
	if err != nil {
		return "", err
	}
	_, ssid, ok := strings.Cut(string(out), ":")
	if !ok {
		return "", nil
	}
	return strings.TrimSpace(ssid), nil
}
