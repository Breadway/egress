//go:build darwin

package platform

import (
	"net"
	"os/exec"
	"strings"
)

// ReadNetworkSignals collects the macOS network picture for netid.
func ReadNetworkSignals(iface, gateway string) NetworkSignals {
	s := NetworkSignals{
		SSID:      SSID(iface),
		GatewayIP: gateway,
		Subnet:    interfaceSubnet(iface),
		Captive:   captiveFingerprint(),
	}
	s.DNSSuffix, s.DHCPServer, s.DNSResolvers = darwinDHCP(iface)
	s.GatewayMAC = darwinGatewayMAC(gateway)
	return s
}

func darwinDHCP(iface string) (suffix, server string, resolvers []string) {
	out, err := exec.Command("ipconfig", "getpacket", iface).Output()
	if err != nil {
		return "", "", nil
	}
	return parseDarwinPacket(string(out))
}

// parseDarwinPacket reads domain_name, domain_search and server_identifier from
// `ipconfig getpacket`. Pure for tests.
func parseDarwinPacket(data string) (suffix, server string, resolvers []string) {
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if i := strings.Index(key, " ("); i >= 0 {
			key = key[:i]
		}
		value = strings.TrimSpace(value)
		switch key {
		case "domain_name", "domain_search":
			if suffix == "" {
				if fields := strings.Fields(value); len(fields) > 0 {
					suffix = strings.TrimSuffix(fields[0], ".")
				}
			}
		case "server_identifier":
			server = value
		case "domain_name_server":
			for _, f := range strings.Fields(strings.ReplaceAll(value, ",", " ")) {
				if net.ParseIP(f) != nil {
					resolvers = append(resolvers, f)
				}
			}
		}
	}
	return suffix, server, resolvers
}

func darwinGatewayMAC(gateway string) string {
	if gateway == "" {
		return ""
	}
	out, err := exec.Command("arp", "-n", gateway).Output()
	if err != nil {
		return ""
	}
	return parseDarwinARP(string(out))
}

// parseDarwinARP finds the MAC in `arp -n <gateway>` output. Pure for tests.
func parseDarwinARP(out string) string {
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "at" {
			if hw, err := net.ParseMAC(fields[i+1]); err == nil && len(hw) == 6 {
				return strings.ToLower(hw.String())
			}
		}
	}
	return ""
}
