//go:build darwin

package platform

import "testing"

func TestParseDefaultRoutesDarwin(t *testing.T) {
	out := "Routing tables\n\nInternet:\n" +
		"Destination        Gateway            Flags        Netif Expire\n" +
		"default            192.168.1.1        UGSc           en0\n" +
		"default            192.168.1.1        UGScI          en1\n" +
		"127                127.0.0.1          UCS            lo0\n"
	routes := parseDefaultRoutesDarwin(out)
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	if routes[0] != (Route{Iface: "en0", Gateway: "192.168.1.1"}) {
		t.Errorf("first route = %+v", routes[0])
	}
	if routes[1] != (Route{Iface: "en1", Gateway: "192.168.1.1"}) {
		t.Errorf("second route = %+v", routes[1])
	}
}
