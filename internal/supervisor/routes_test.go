package supervisor

import (
	"testing"

	"egress/internal/platform"
)

func TestSameRouteSet(t *testing.T) {
	a := []platform.Route{{Iface: "eth0", Gateway: "192.168.1.1"}, {Iface: "wlan0", Gateway: "192.168.1.1"}}
	b := []platform.Route{{Iface: "wlan0", Gateway: "192.168.1.1"}, {Iface: "eth0", Gateway: "192.168.1.1"}}
	if !sameRouteSet(a, b) {
		t.Error("same routes in different order should match")
	}
	if sameRouteSet(a, a[:1]) {
		t.Error("different sizes should not match")
	}
	if sameRouteSet(a, []platform.Route{{Iface: "eth0", Gateway: "10.0.0.1"}, {Iface: "wlan0", Gateway: "192.168.1.1"}}) {
		t.Error("different gateways should not match")
	}
	if !sameRouteSet(nil, nil) {
		t.Error("two empty sets should match")
	}
	dup := []platform.Route{{Iface: "eth0", Gateway: "1.1.1.1"}, {Iface: "eth0", Gateway: "1.1.1.1"}}
	if !sameRouteSet(dup, append([]platform.Route(nil), dup...)) {
		t.Error("identical duplicates should match")
	}
	if sameRouteSet(dup, dup[:1]) {
		t.Error("duplicate count must matter")
	}
}
