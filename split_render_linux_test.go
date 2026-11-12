//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestRenderWGConfigSplit(t *testing.T) {
	cfg := tunnelConfig{
		PrivateKey: "key",
		ClientIP:   "10.88.0.2",
		Endpoint:   aegisIPv4 + ":" + aegisWGPort,
		Split:      true,
	}
	got := renderWGConfig(cfg)
	if strings.Contains(got, "0.0.0.0/1") || strings.Contains(got, "128.0.0.0/1") {
		t.Error("split config must not install half-default routes")
	}
	if !strings.Contains(got, tunnelSubnet+" dev %i") {
		t.Error("split config must route the tunnel subnet")
	}
	if !strings.Contains(got, "AllowedIPs = 0.0.0.0/0") {
		t.Error("split config keeps all destinations allowed; routes decide")
	}

	full := renderWGConfig(tunnelConfig{PrivateKey: "key", ClientIP: "10.88.0.2", Endpoint: cfg.Endpoint})
	if !strings.Contains(full, "0.0.0.0/1") || !strings.Contains(full, "128.0.0.0/1") {
		t.Error("full config must keep the half-default routes")
	}
}
