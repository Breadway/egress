//go:build linux

package platform

import (
	"os/exec"
	"strings"
)

// SSID returns the current Wi-Fi network name for iface, or empty when the
// link is wired or the tools cannot read it. An empty iface asks for whichever
// wireless link is associated. The shared split table keys on this instead of
// the DHCP gateway, which can change on the same network.
func SSID(iface string) string {
	if iface != "" {
		if out, err := exec.Command("iw", "dev", iface, "link").Output(); err == nil {
			if ssid := parseIWSSID(string(out)); ssid != "" {
				return ssid
			}
		}
		if out, err := exec.Command("iwgetid", "-r", iface).Output(); err == nil {
			if ssid := strings.TrimSpace(string(out)); ssid != "" {
				return ssid
			}
		}
	} else if out, err := exec.Command("iwgetid", "-r").Output(); err == nil {
		if ssid := strings.TrimSpace(string(out)); ssid != "" {
			return ssid
		}
	}
	if out, err := exec.Command("nmcli", "-t", "-f", "active,ssid", "dev", "wifi").Output(); err == nil {
		if ssid := parseNmcliSSID(string(out)); ssid != "" {
			return ssid
		}
	}
	return ""
}

// parseIWSSID reads the SSID line from `iw dev <iface> link`. Pure for tests.
func parseIWSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if ssid, ok := strings.CutPrefix(line, "SSID:"); ok {
			return strings.TrimSpace(ssid)
		}
	}
	return ""
}

// parseNmcliSSID picks the active row from `nmcli -t -f active,ssid dev wifi`.
func parseNmcliSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if ssid, ok := strings.CutPrefix(strings.TrimSpace(line), "yes:"); ok {
			return strings.TrimSpace(ssid)
		}
	}
	return ""
}
