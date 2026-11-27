//go:build darwin

package platform

import (
	"os/exec"
	"strings"
)

// SSID returns the current Wi-Fi network name, or empty for a wired link.
func SSID(iface string) string {
	if iface == "" {
		iface = "en0"
	}
	if out, err := exec.Command("networksetup", "-getairportnetwork", iface).Output(); err == nil {
		if ssid := parseAirportSSID(string(out)); ssid != "" {
			return ssid
		}
	}
	if out, err := exec.Command("airport", "-I").Output(); err == nil {
		if ssid := parseAirportInfoSSID(string(out)); ssid != "" {
			return ssid
		}
	}
	return ""
}

func parseAirportSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if ssid, ok := strings.CutPrefix(strings.TrimSpace(line), "Current Wi-Fi Network:"); ok {
			return strings.TrimSpace(ssid)
		}
	}
	return ""
}

func parseAirportInfoSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if ssid, ok := strings.CutPrefix(strings.TrimSpace(line), "SSID:"); ok {
			return strings.TrimSpace(ssid)
		}
	}
	return ""
}
