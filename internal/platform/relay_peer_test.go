package platform

import "testing"

const testRelayConf = `[Interface]
PrivateKey = x

[Peer]
PublicKey = A
AllowedIPs = 10.0.0.1/32, 10.0.0.2/32
Endpoint = 203.0.113.9:51820

[Peer]
PublicKey = B
AllowedIPs = 10.88.0.0/24
`

func TestPeerAllowedIPs(t *testing.T) {
	got := peerAllowedIPs(testRelayConf, "A")
	if len(got) != 2 || !got["10.0.0.1/32"] || !got["10.0.0.2/32"] {
		t.Fatalf("allowed = %+v", got)
	}
	if got := peerAllowedIPs(testRelayConf, "missing"); len(got) != 0 {
		t.Fatalf("missing peer allowed = %+v", got)
	}
}

func TestAllowedAdds(t *testing.T) {
	before := peerAllowedIPs(testRelayConf, "A")
	cases := []struct {
		after []string
		want  bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{"10.0.0.1/32"}, false},
		{[]string{"10.0.0.1/32", "10.0.0.2/32"}, false},
		{[]string{"10.0.0.1/32", "10.0.0.3/32"}, true},
		{[]string{"198.51.100.7/32"}, true},
	}
	for _, c := range cases {
		if got := allowedAdds(before, c.after); got != c.want {
			t.Errorf("allowedAdds(%v) = %v, want %v", c.after, got, c.want)
		}
	}
}

func TestRenderRelayPeerRewritesAllowed(t *testing.T) {
	updated, changed := renderRelayPeer(testRelayConf, "A", "127.0.0.1:7109", []string{"10.0.0.3/32"})
	if !changed {
		t.Fatal("config should change")
	}
	if got := peerAllowedIPs(updated, "A"); len(got) != 1 || !got["10.0.0.3/32"] {
		t.Fatalf("rewritten allowed = %+v", got)
	}
	// The other peer is untouched.
	if got := peerAllowedIPs(updated, "B"); !got["10.88.0.0/24"] {
		t.Fatalf("peer B changed: %+v", got)
	}
}
