package platform

import "testing"

func TestDNSServersPointAtListener(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{"darwin dhcp", "There aren't any DNS Servers set on Wi-Fi.\n", false},
		{"darwin set", "192.168.1.1\n8.8.8.8\n", false},
		{"darwin ours", "127.0.0.1\n", true},
		{"windows dhcp", "192.168.1.1\r\n", false},
		{"windows ours", "127.0.0.1\r\n", true},
		{"windows mixed", "192.168.1.1\r\n127.0.0.1\r\n", true},
		{"empty", "", false},
		{"prefix trap", "127.0.0.10\n", false},
	}
	for _, tc := range cases {
		if got := DNSServersPointAtListener(tc.output); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
