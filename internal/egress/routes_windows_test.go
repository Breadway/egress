//go:build windows

package egress

import "testing"

func TestParseDefaultRoutesWindows(t *testing.T) {
	out := "5 10.179.160.1\r\n10 192.168.1.1\r\n\r\nnot a route\nabc def\r\n7 not-an-ip\r\n"
	routes := parseDefaultRoutesWindows(out)
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	if routes[0] != (Route{Iface: "5", Gateway: "10.179.160.1"}) {
		t.Errorf("first route = %+v", routes[0])
	}
	if routes[1] != (Route{Iface: "10", Gateway: "192.168.1.1"}) {
		t.Errorf("second route = %+v", routes[1])
	}
}
