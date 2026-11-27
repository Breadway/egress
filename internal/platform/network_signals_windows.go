//go:build windows

package platform

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// ReadNetworkSignals collects the Windows network picture for netid.
func ReadNetworkSignals(iface, gateway string) NetworkSignals {
	s := NetworkSignals{
		SSID:      SSID(""),
		GatewayIP: gateway,
		Subnet:    windowsSubnet(iface),
		Captive:   captiveFingerprint(),
	}
	s.DNSSuffix, s.DHCPServer, s.DNSResolvers = windowsDHCP()
	s.GatewayMAC = windowsGatewayMAC(gateway)
	return s
}

func windowsSubnet(iface string) string {
	index, err := strconv.Atoi(iface)
	if err != nil {
		return ""
	}
	i, err := net.InterfaceByIndex(index)
	if err != nil {
		return ""
	}
	return subnetForInterface(i)
}

func windowsDHCP() (suffix, server string, resolvers []string) {
	out, err := exec.Command("ipconfig", "/all").Output()
	if err != nil {
		return "", "", nil
	}
	return parseIPConfig(string(out))
}

// parseIPConfig reads the first DNS suffix, DHCP server and DNS server list
// from `ipconfig /all`. Pure for tests.
func parseIPConfig(data string) (suffix, server string, resolvers []string) {
	for _, line := range strings.Split(data, "\n") {
		label, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		label = strings.ToLower(strings.TrimSpace(label))
		value = strings.TrimSpace(value)
		switch {
		case strings.Contains(label, "connection-specific dns suffix"):
			if suffix == "" {
				suffix = strings.TrimSuffix(value, ".")
			}
		case strings.Contains(label, "dns suffix search list"):
			if suffix == "" {
				if fields := strings.Fields(value); len(fields) > 0 {
					suffix = strings.TrimSuffix(fields[0], ".")
				}
			}
		case strings.Contains(label, "dhcp server"):
			if server == "" {
				server = value
			}
		case strings.Contains(label, "dns servers"):
			if ip := net.ParseIP(value); ip != nil {
				resolvers = append(resolvers, value)
			}
		}
	}
	return suffix, server, resolvers
}

func windowsGatewayMAC(gateway string) string {
	if gateway == "" {
		return ""
	}
	out, err := exec.Command("arp", "-a", gateway).Output()
	if err != nil {
		return ""
	}
	return parseWindowsARP(string(out))
}

// parseWindowsARP finds the MAC in `arp -a <gateway>` output. Pure for tests.
func parseWindowsARP(out string) string {
	for _, field := range strings.Fields(out) {
		mac := strings.NewReplacer("-", ":", ".", ":").Replace(field)
		if hw, err := net.ParseMAC(mac); err == nil && len(hw) == 6 {
			return strings.ToLower(hw.String())
		}
	}
	return ""
}
