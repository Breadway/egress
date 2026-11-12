//go:build linux

package platform

import "testing"

func TestResolvConfPointsAtListener(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"ours", "nameserver 127.0.0.1\noptions edns0 trust-ad\n", true},
		{"foreign", "nameserver 8.8.8.8\n", false},
		{"commented", "# nameserver 127.0.0.1\nnameserver 8.8.8.8\n", false},
		{"empty", "", false},
		{"ours second", "nameserver 8.8.8.8\nnameserver 127.0.0.1\n", true},
		{"loopback with port suffix ignored", "nameserver 127.0.0.2\n", false},
	}
	for _, tc := range cases {
		if got := resolvConfPointsAtListener([]byte(tc.data)); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
