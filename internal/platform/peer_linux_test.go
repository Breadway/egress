//go:build linux

package platform

import (
	"egress/internal/core"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestHasOurPeer builds a bare wg0 husk like the one NetworkManager
// autoconnect left behind, and checks the peer guard rejects it, accepts it
// once our peer is configured, and rejects it again after removal. Root
// only; touches no network and no routes.
func TestHasOurPeer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := os.Stat("/sys/class/net/" + core.WGInterface); err == nil {
		t.Skipf("%s exists; refusing to disturb a live tunnel", core.WGInterface)
	}
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %s: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	run("ip", "link", "add", "dev", core.WGInterface, "type", "wireguard")
	defer exec.Command("ip", "link", "del", "dev", core.WGInterface).Run()

	p := linuxPlatform{}
	if p.hasOurPeer() {
		t.Error("bare husk interface reports our peer")
	}
	run("wg", "set", core.WGInterface, "peer", core.AegisPublicKey, "endpoint", "127.0.0.1:9", "allowed-ips", "10.88.0.9/32")
	if !p.hasOurPeer() {
		t.Error("configured interface does not report our peer")
	}
	run("wg", "set", core.WGInterface, "peer", core.AegisPublicKey, "remove")
	if p.hasOurPeer() {
		t.Error("interface reports our peer after removal")
	}
}

// TestRepinEndpoint deletes the Aegis host route and checks the helper
// restores it via the current default gateway. This is the roam path: the
// PostUp pin points at a dead interface and the supervisor must refresh it.
// TestParseDefaultRoutesLinux checks metric ordering and malformed lines.
func TestParseDefaultRoutesLinux(t *testing.T) {
	out := []byte("default via 192.168.1.1 dev eth0 proto dhcp metric 100\n" +
		"default via 10.179.160.1 dev wlan0 proto dhcp metric 20600\n" +
		"default dev lo scope link\n" +
		"10.0.0.0/8 dev eth0 proto kernel scope link\n")
	routes, err := parseDefaultRoutesLinux(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	if routes[0] != (Route{Iface: "eth0", Gateway: "192.168.1.1"}) {
		t.Errorf("first route = %+v, want eth0/192.168.1.1", routes[0])
	}
	if routes[1] != (Route{Iface: "wlan0", Gateway: "10.179.160.1"}) {
		t.Errorf("second route = %+v, want wlan0/10.179.160.1", routes[1])
	}
}

func TestRepinEndpoint(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		t.Skipf("no default route: %v", err)
	}
	var gateway, iface string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "default" {
			continue
		}
		for i := 1; i < len(fields)-1; i++ {
			switch fields[i] {
			case "via":
				gateway = fields[i+1]
			case "dev":
				iface = fields[i+1]
			}
		}
		if iface != "" {
			break
		}
	}
	if gateway == "" || iface == "" {
		t.Skip("no usable default route")
	}

	exec.Command("ip", "route", "del", core.AegisIPv4).Run()
	p := linuxPlatform{}
	if err := p.RepinEndpoint(gateway, iface); err != nil {
		t.Fatalf("RepinEndpoint: %v", err)
	}
	got, err := exec.Command("ip", "route", "get", core.AegisIPv4).CombinedOutput()
	if err != nil {
		t.Fatalf("ip route get: %v", err)
	}
	if !strings.Contains(string(got), "via "+gateway) || !strings.Contains(string(got), "dev "+iface) {
		t.Errorf("pin not restored via %s dev %s: %s", gateway, iface, strings.TrimSpace(string(got)))
	}
	exec.Command("ip", "route", "del", core.AegisIPv4).Run()
}
