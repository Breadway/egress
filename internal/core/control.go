package core

import (
	"context"
	"net"
	"time"
)

// controlHosts are Aegis-hosted names. Their public addresses can be blocked
// by a restrictive network while the authenticated tunnel to Aegis is up, so
// their HTTP clients prefer the tunnel address and fall back to the public
// path only if the tunnel dial fails.
var controlHosts = map[string]bool{
	"bypass.breadway.dev": true,
	"dns.breadway.dev":    true,
}

// ControlDialContext connects Aegis control-plane traffic through the WireGuard
// tunnel first. The TLS server name still comes from the URL, so the public
// certificate validates against the tunnel address. Non-control hosts and a
// down tunnel keep the previous direct behaviour.
func ControlDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if host, _, err := net.SplitHostPort(addr); err == nil && controlHosts[host] {
		tunnel := &net.Dialer{Timeout: 3 * time.Second}
		if conn, derr := tunnel.DialContext(ctx, network, net.JoinHostPort(AegisTunnelIP, "443")); derr == nil {
			return conn, nil
		}
	}
	direct := &net.Dialer{Timeout: 10 * time.Second}
	return direct.DialContext(ctx, network, addr)
}
