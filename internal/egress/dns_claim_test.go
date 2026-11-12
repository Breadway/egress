//go:build linux

package egress

import "testing"

func TestParseDefaultRouteLinks(t *testing.T) {
	cases := []struct {
		name string
		out  string
		skip string
		want []string
	}{
		{
			name: "dhcp wifi",
			out:  "default via 10.179.160.1 dev wlan0 proto dhcp src 10.179.161.89 metric 600\n",
			skip: "wg0",
			want: []string{"wlan0"},
		},
		{
			name: "two defaults",
			out:  "default via 192.168.1.1 dev eth0 metric 100\ndefault via 10.0.0.1 dev wlan0 metric 600\n",
			skip: "wg0",
			want: []string{"eth0", "wlan0"},
		},
		{
			name: "same device twice",
			out:  "default via 1.1.1.1 dev wlan0 metric 100\ndefault via 2.2.2.2 dev wlan0 metric 600\n",
			skip: "wg0",
			want: []string{"wlan0"},
		},
		{
			name: "tunnel is skipped",
			out:  "default dev wg0 scope link\n",
			skip: "wg0",
			want: nil,
		},
		{
			name: "no default route",
			out:  "",
			skip: "wg0",
			want: nil,
		},
	}
	for _, tc := range cases {
		got := parseDefaultRouteLinks(tc.out, tc.skip)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}

func TestLinkUsesListener(t *testing.T) {
	cases := []struct {
		name   string
		dns    string
		domain string
		want   bool
	}{
		{
			name:   "claimed",
			dns:    "Link 2 (wlan0): 127.0.0.1:7103\n",
			domain: "Link 2 (wlan0): ~.\n",
			want:   true,
		},
		{
			name:   "dhcp resolver wins",
			dns:    "Link 2 (wlan0): 10.251.2.7 10.251.2.8\n",
			domain: "Link 2 (wlan0): ~.\n",
			want:   false,
		},
		{
			name:   "listener but no catch-all domain",
			dns:    "Link 2 (wlan0): 127.0.0.1:7103\n",
			domain: "Link 2 (wlan0): ncc.wa.edu.au\n",
			want:   false,
		},
		{
			name:   "prefix trap",
			dns:    "Link 2 (wlan0): 127.0.0.10:7103\n",
			domain: "Link 2 (wlan0): ~.\n",
			want:   false,
		},
		{
			name:   "domain list with catch-all",
			dns:    "Link 2 (wlan0): 127.0.0.1:7103\n",
			domain: "Link 2 (wlan0): ncc.wa.edu.au ~.\n",
			want:   true,
		},
	}
	for _, tc := range cases {
		if got := linkUsesListener(tc.dns, tc.domain); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
