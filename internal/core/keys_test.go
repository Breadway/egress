package core

import (
	"strings"
	"testing"
)

func TestRenderWGConfigAllowedIPs(t *testing.T) {
	full := RenderWGConfig(TunnelConfig{PrivateKey: "k", ClientIP: "10.88.0.2", Endpoint: "1.2.3.4:51820"})
	if !strings.Contains(full, "AllowedIPs = 0.0.0.0/0") {
		t.Fatal("a full install must keep the default AllowedIPs")
	}
	split := RenderWGConfig(TunnelConfig{
		PrivateKey: "k", ClientIP: "10.88.0.2", Endpoint: "1.2.3.4:51820",
		Split: true, AllowedIPs: TunnelSubnet,
	})
	if !strings.Contains(split, "AllowedIPs = "+TunnelSubnet) {
		t.Fatal("a split install must claim only the tunnel subnet")
	}
	if strings.Contains(split, "AllowedIPs = 0.0.0.0/0") {
		t.Fatal("a split install must not claim every destination")
	}
}
