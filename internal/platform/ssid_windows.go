//go:build windows

package platform

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// SSID returns the current Wi-Fi network name, or empty for a wired link.
// netsh reports whichever WLAN interface is connected, so a wired default
// route must not borrow its name.
func SSID(iface string) string {
	if !isWirelessIface(iface) {
		return ""
	}
	out, err := exec.Command("netsh", "wlan", "show", "interfaces").Output()
	if err != nil {
		return ""
	}
	return parseNetshSSID(string(out))
}

// isWirelessIface checks the adapter's friendly name. An unknown index still
// tries netsh, which is better than silently dropping Wi-Fi identity.
func isWirelessIface(iface string) bool {
	index, err := strconv.Atoi(iface)
	if err != nil {
		return true
	}
	i, err := net.InterfaceByIndex(index)
	if err != nil {
		return true
	}
	name := strings.ToLower(i.Name)
	for _, hint := range []string{"wi-fi", "wifi", "wlan", "wireless"} {
		if strings.Contains(name, hint) {
			return true
		}
	}
	return false
}

// parseNetshSSID reads the first SSID field, skipping BSSID. Pure for tests.
func parseNetshSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "SSID") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
