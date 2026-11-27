//go:build linux

package platform

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ReadNetworkSignals collects the Linux network picture for netid.
func ReadNetworkSignals(iface, gateway string) NetworkSignals {
	s := NetworkSignals{
		SSID:       SSID(iface),
		GatewayIP:  gateway,
		Subnet:     interfaceSubnet(iface),
		Captive:    captiveFingerprint(),
		GatewayMAC: gatewayMAC(gateway),
	}
	s.DNSSuffix, s.DHCPServer, s.DNSResolvers = linuxDHCP(iface)
	return s
}

func linuxDHCP(iface string) (suffix, server string, resolvers []string) {
	index := ""
	if i, err := net.InterfaceByName(iface); err == nil {
		index = strconv.Itoa(i.Index)
	}
	// systemd-networkd keeps one lease per interface index. Without an index
	// there is no way to know which lease belongs to this link, so fall
	// through to NetworkManager and the resolver.
	for _, dir := range []string{"/run/systemd/netif/leases", "/var/lib/systemd/network/leases"} {
		if index == "" {
			break
		}
		data, err := os.ReadFile(filepath.Join(dir, index))
		if err != nil {
			continue
		}
		if sfx, srv, dns, ok := parseSystemdLease(string(data)); ok {
			return sfx, srv, dns
		}
	}
	// NetworkManager stores key/value leases.
	files, _ := filepath.Glob("/var/lib/NetworkManager/*.lease")
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if sfx, srv, dns, ok := parseNMLease(string(data)); ok {
			return sfx, srv, dns
		}
	}
	// NetworkManager stores address leases without the option list; the live
	// DHCP4 options are the authoritative suffix, server and resolver source.
	if sfx, srv, dns := nmcliDHCP(iface); sfx != "" || srv != "" || len(dns) > 0 {
		return sfx, srv, dns
	}
	// Last resort: the resolver search list. Egress and Tailscale own this
	// file on some installs, so ignore their suffixes.
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && (fields[0] == "search" || fields[0] == "domain") {
				for _, d := range fields[1:] {
					if strings.HasSuffix(d, ".ts.net") || strings.HasSuffix(d, ".tailscale.net") {
						continue
					}
					return strings.TrimSuffix(d, "."), "", nil
				}
			}
			if len(fields) >= 2 && fields[0] == "nameserver" && !strings.HasPrefix(fields[1], "127.") && fields[1] != "::1" {
				resolvers = append(resolvers, fields[1])
			}
		}
	}
	return "", "", resolvers
}

// parseSystemdLease reads DOMAINNAME, DOMAIN_SEARCH, SERVER_ADDRESS and DNS
// from a systemd-networkd lease. Pure for tests.
func parseSystemdLease(data string) (suffix, server string, resolvers []string, ok bool) {
	for _, line := range strings.Split(data, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "DOMAINNAME", "DOMAIN_SEARCH":
			if suffix == "" {
				if fields := strings.Fields(value); len(fields) > 0 {
					suffix = strings.TrimSuffix(fields[0], ".")
				}
			}
		case "SERVER_ADDRESS":
			server = value
		case "DNS":
			resolvers = append(resolvers, strings.Fields(value)...)
		}
	}
	return suffix, server, resolvers, suffix != "" || server != "" || len(resolvers) > 0
}

// parseNMLease reads NetworkManager's key/value lease format.
func parseNMLease(data string) (suffix, server string, resolvers []string, ok bool) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "domain "):
			suffix = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "domain ")), ".")
		case strings.HasPrefix(line, "dhcp-server-identifier "):
			server = strings.TrimSpace(strings.TrimPrefix(line, "dhcp-server-identifier "))
		case strings.HasPrefix(line, "dhcp-option=option:domain-search "):
			suffix = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "dhcp-option=option:domain-search ")), ".")
		case strings.HasPrefix(line, "dhcp-option=option:dns-server "):
			resolvers = strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "dhcp-option=option:dns-server ")), ",")
		}
	}
	return suffix, server, resolvers, suffix != "" || server != "" || len(resolvers) > 0
}

// nmcliDHCP reads the live DHCP options from NetworkManager. The lease files
// under /var/lib/NetworkManager only carry ADDRESS on current releases.
func nmcliDHCP(iface string) (suffix, server string, resolvers []string) {
	out, err := exec.Command("nmcli", "-f", "DHCP4", "dev", "show", iface).Output()
	if err != nil {
		return "", "", nil
	}
	return parseNmcliDHCP(string(out))
}

// parseNmcliDHCP reads dhcp_server_identifier, domain_search and
// domain_name_servers from `nmcli -f DHCP4 dev show`. Pure for tests.
func parseNmcliDHCP(data string) (suffix, server string, resolvers []string) {
	for _, line := range strings.Split(data, "\n") {
		_, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(rest), "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "dhcp_server_identifier":
			server = value
		case "domain_search", "domain_name":
			if suffix == "" {
				if fields := strings.Fields(value); len(fields) > 0 {
					suffix = strings.TrimSuffix(fields[0], ".")
				}
			}
		case "domain_name_servers":
			for _, field := range strings.Fields(strings.ReplaceAll(value, ",", " ")) {
				if net.ParseIP(field) != nil {
					resolvers = append(resolvers, field)
				}
			}
		}
	}
	return suffix, server, resolvers
}

// gatewayMAC reads the neighbor entry for the gateway. A UDP dial populates the
// ARP cache when the entry has expired.
func gatewayMAC(gateway string) string {
	if gateway == "" {
		return ""
	}
	if mac := readNeighbor(gateway); mac != "" {
		return mac
	}
	// A failed UDP dial is fine: it only exists to trigger ARP resolution.
	if conn, err := net.DialTimeout("udp", net.JoinHostPort(gateway, "9"), 300*time.Millisecond); err == nil {
		conn.Close()
	}
	return readNeighbor(gateway)
}

func readNeighbor(gateway string) string {
	out, err := exec.Command("ip", "neigh", "show", gateway).Output()
	if err != nil {
		return ""
	}
	return parseIPNeighMAC(string(out))
}

// parseIPNeighMAC returns the lladdr from `ip neigh show`. Pure for tests.
func parseIPNeighMAC(out string) string {
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "lladdr" {
			return strings.ToLower(fields[i+1])
		}
	}
	return ""
}
