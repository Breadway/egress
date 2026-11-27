//go:build linux

package platform

import "testing"

func TestParseSystemdLease(t *testing.T) {
	data := "DOMAINNAME=school.example\nSERVER_ADDRESS=10.179.160.1\nDNS=10.179.160.1 9.9.9.9\n"
	suffix, server, dns, ok := parseSystemdLease(data)
	if !ok || suffix != "school.example" || server != "10.179.160.1" || len(dns) != 2 {
		t.Fatalf("lease = %q %q %v %v", suffix, server, dns, ok)
	}
}

func TestParseNMLease(t *testing.T) {
	data := "domain school.example\ndhcp-server-identifier 10.0.0.1\ndhcp-option=option:dns-server 1.1.1.1,8.8.8.8\n"
	suffix, server, dns, ok := parseNMLease(data)
	if !ok || suffix != "school.example" || server != "10.0.0.1" || len(dns) != 2 {
		t.Fatalf("nm lease = %q %q %v %v", suffix, server, dns, ok)
	}
}

func TestParseNmcliDHCP(t *testing.T) {
	data := `DHCP4.OPTION[1]:                        dhcp_server_identifier = 10.179.160.1
DHCP4.OPTION[2]:                        domain_name_servers = 172.64.36.1 172.64.36.2
DHCP4.OPTION[3]:                        domain_search = ncc.wa.edu.au
DHCP4.OPTION[4]:                        routers = 10.179.160.1
`
	suffix, server, dns := parseNmcliDHCP(data)
	if suffix != "ncc.wa.edu.au" || server != "10.179.160.1" || len(dns) != 2 {
		t.Fatalf("nmcli dhcp = %q %q %v", suffix, server, dns)
	}
}

func TestParseIPNeighMAC(t *testing.T) {
	out := "10.179.160.1 dev wlan0 lladdr A2:05:D6:DC:BF:CB REACHABLE"
	if got := parseIPNeighMAC(out); got != "a2:05:d6:dc:bf:cb" {
		t.Fatalf("mac = %q", got)
	}
}

func TestParseIWSSID(t *testing.T) {
	out := "Connected to a2:05:d6:dc:bf:cb (on wlan0)\n\tSSID: NCC\n\tfreq: 5320.0\n"
	if got := parseIWSSID(out); got != "NCC" {
		t.Fatalf("ssid = %q", got)
	}
}

func TestParseNmcliSSID(t *testing.T) {
	out := "no:Other\nyes:NCC\nno:Third\n"
	if got := parseNmcliSSID(out); got != "NCC" {
		t.Fatalf("ssid = %q", got)
	}
}
