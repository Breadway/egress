// Package core holds the constants and value types shared by every other
// package in egress. It exists so the packages above it can depend on
// something instead of each other.
package core

import "time"

const (
	DoHURL        = "https://dns.breadway.dev/dns-query"
	DoHHost       = "dns.breadway.dev"
	DoHListenAddr = "127.0.0.1:7103"

	AegisIPv4      = "152.69.174.7"
	AegisWGPort    = "7105"
	AegisTunnelIP  = "10.88.0.1"
	AegisPublicKey = "MsU+DNi9YLMpLfsHifP2+nMLAiblNs0uvPsQs/U2ZUA="
	WGInterface    = "wg0"
	TunnelSubnet   = "10.88.0.0/24"

	WstunnelPrefix  = "wg-tunnel"
	RelayHost       = "127.0.0.1"
	RelayPort       = "7108"
	DefaultClientIP = "10.88.0.4"

	ReportURL  = "https://bypass.breadway.dev/api/report"
	ReportHost = "bypass.breadway.dev"

	ProbeInterval = 15 * time.Second
	TrialInterval = 10 * time.Minute

	RelayProbeWindow   = 5 * time.Second
	RelayFailThreshold = 2
	DNSCheckEvery      = 60 * time.Second

	DoHResetAfterFailures = 3
	DoHRecoverEvery       = 60 * time.Second
	DoHWedgeRestartAfter  = 5 * time.Minute
)

// TunnelConfig is everything needed to write a WireGuard configuration.
type TunnelConfig struct {
	PrivateKey string
	ClientIP   string
	Endpoint   string
	// Split keeps the default route off the tunnel: only host routes added by
	// the split controller send destinations into wg0.
	Split bool
	// ReportPubkey identifies the device in install reports when the
	// invocation has no private key.
	ReportPubkey string
}

func (c TunnelConfig) DirectEndpoint() string { return AegisIPv4 + ":" + AegisWGPort }
func (c TunnelConfig) RelayEndpoint() string  { return RelayHost + ":" + RelayPort }
