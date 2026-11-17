package core

import (
	"context"
	"net"
	"time"
)

// LocalResolver resolves through this machine's own DoH listener instead of
// /etc/resolv.conf. egress must not depend on the system resolver for its own
// lookups: another manager (Tailscale MagicDNS took the file over and its
// server stopped answering) can leave the file pointing somewhere unreachable,
// and then the feed, the probes and the scan all fail while the tunnel is fine.
func LocalResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, DoHListenAddr)
		},
	}
}

// LookupHost resolves through the local listener, falling back to the system
// resolver only when the listener is not answering (the service may be down
// while a CLI command that needs a name is run).
func LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := LocalResolver().LookupIP(ctx, "ip", host)
	if err == nil && len(ips) > 0 {
		return ips, nil
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}
