package split

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"time"

	"egress/internal/core"
)

// ProbeProtocols reports which outbound protocols this network allows. The
// answer is shared with other devices on the same network id, so a client
// joining a filtered network can start in the right mode instead of
// rediscovering a UDP block on its first failed lookup.
//
// States are "ok", "blocked", or "unknown"; evidence is short and safe to
// store.
func ProbeProtocols(ctx context.Context) []splitProtocolReport {
	out := make([]splitProtocolReport, 0, 4)
	out = append(out, probeTCP(ctx))
	out = append(out, probeUDP(ctx))
	out = append(out, probeDNS(ctx))
	out = append(out, probeICMP(ctx))
	return out
}

func probeTCP(ctx context.Context) splitProtocolReport {
	target := net.JoinHostPort(core.AegisIPv4, "443")
	d := net.Dialer{Timeout: 4 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return splitProtocolReport{Protocol: "tcp", State: "blocked", Evidence: "connect-failed"}
	}
	_ = conn.Close()
	return splitProtocolReport{Protocol: "tcp", State: "ok", Evidence: "connect"}
}

// probeUDP sends one DNS query over UDP to a public resolver. A reply proves
// outbound UDP works; silence is a block or a dropped response, so it is
// reported as blocked with weak evidence.
func probeUDP(ctx context.Context) splitProtocolReport {
	d := net.Dialer{Timeout: 4 * time.Second}
	conn, err := d.DialContext(ctx, "udp", "1.1.1.1:53")
	if err != nil {
		return splitProtocolReport{Protocol: "udp", State: "blocked", Evidence: "dial-failed"}
	}
	defer conn.Close()
	query := dnsQuery("example.com")
	deadline := time.Now().Add(4 * time.Second)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(query); err != nil {
		return splitProtocolReport{Protocol: "udp", State: "blocked", Evidence: "write-failed"}
	}
	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err != nil {
		return splitProtocolReport{Protocol: "udp", State: "blocked", Evidence: "no-reply"}
	}
	return splitProtocolReport{Protocol: "udp", State: "ok", Evidence: "dns-reply"}
}

func probeDNS(ctx context.Context) splitProtocolReport {
	resolver := net.Resolver{}
	lookupCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if _, err := resolver.LookupHost(lookupCtx, "example.com"); err != nil {
		return splitProtocolReport{Protocol: "dns", State: "blocked", Evidence: "lookup-failed"}
	}
	return splitProtocolReport{Protocol: "dns", State: "ok", Evidence: "lookup"}
}

// probeICMP shells out: raw sockets need privileges the proxy does not have,
// and ping is present on the platforms this client ships for.
func probeICMP(ctx context.Context) splitProtocolReport {
	if runtime.GOOS == "windows" {
		out, err := exec.CommandContext(ctx, "ping", "-n", "1", "-w", "2000", core.AegisIPv4).CombinedOutput()
		if err != nil && len(out) == 0 {
			return splitProtocolReport{Protocol: "icmp", State: "unknown", Evidence: "no-ping"}
		}
		if err != nil {
			return splitProtocolReport{Protocol: "icmp", State: "blocked", Evidence: "no-reply"}
		}
		return splitProtocolReport{Protocol: "icmp", State: "ok", Evidence: "reply"}
	}
	count := "-c"
	if runtime.GOOS == "darwin" {
		count = "-c"
	}
	out, err := exec.CommandContext(ctx, "ping", count, "1", "-W", "2", core.AegisIPv4).CombinedOutput()
	if err != nil && len(out) == 0 {
		return splitProtocolReport{Protocol: "icmp", State: "unknown", Evidence: "no-ping"}
	}
	if err != nil {
		return splitProtocolReport{Protocol: "icmp", State: "blocked", Evidence: "no-reply"}
	}
	return splitProtocolReport{Protocol: "icmp", State: "ok", Evidence: "reply"}
}

// dnsQuery builds a minimal A query for name.
func dnsQuery(name string) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range splitLabels(name) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00, 0x00, 0x01, 0x00, 0x01)
	return msg
}

func splitLabels(name string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	return labels
}
