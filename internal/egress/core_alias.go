package egress

import (
	"egress/internal/wstunnel"
	"log"
	"net"
	"time"

	"egress/internal/core"
)

// The shared constants and value types live in internal/core so the packages
// above it can depend on one thing. These aliases keep the names used
// throughout this package, and are removed as each file moves out.
const (
	dohURL        = core.DoHURL
	dohHost       = core.DoHHost
	dohListenAddr = core.DoHListenAddr

	aegisIPv4      = core.AegisIPv4
	aegisWGPort    = core.AegisWGPort
	aegisTunnelIP  = core.AegisTunnelIP
	aegisPublicKey = core.AegisPublicKey
	wgInterface    = core.WGInterface
	tunnelSubnet   = core.TunnelSubnet

	wstunnelPrefix  = core.WstunnelPrefix
	relayHost       = core.RelayHost
	relayPort       = core.RelayPort
	defaultClientIP = core.DefaultClientIP

	reportURL  = core.ReportURL
	reportHost = core.ReportHost

	probeInterval = core.ProbeInterval
	trialInterval = core.TrialInterval

	relayProbeWindow   = core.RelayProbeWindow
	relayFailThreshold = core.RelayFailThreshold
	dnsCheckEvery      = core.DNSCheckEvery

	dohResetAfterFailures = core.DoHResetAfterFailures
	dohRecoverEvery       = core.DoHRecoverEvery
	dohWedgeRestartAfter  = core.DoHWedgeRestartAfter
)

type tunnelConfig = core.TunnelConfig

var _ = time.Second

// DNS wire helpers live in core so the resolver can use them without
// importing this package.
func NormalizeDomain(s string) string                  { return core.NormalizeDomain(s) }
func dnsQueryName(q []byte) string                     { return core.DNSQueryName(q) }
func dnsAnswerIPv4(r []byte) ([]net.IP, time.Duration) { return core.DNSAnswerIPv4(r) }

// wstunnel helpers live in internal/wstunnel so the platform layer can use
// them without importing this package.
func wstunnelExeName() string           { return wstunnel.ExeName() }
func findWstunnel() (string, error)     { return wstunnel.Find() }
func ensureWstunnel() (string, error)   { return wstunnel.Ensure() }
func downloadWstunnel() (string, error) { return wstunnel.Download() }

type wstunnelProc = wstunnel.Proc

func newWstunnelProc(path string, logger *log.Logger) *wstunnelProc {
	return wstunnel.NewProc(path, logger)
}

func normalizeKey(s string) (string, error)     { return core.NormalizeKey(s) }
func publicKey(k string) (string, error)        { return core.PublicKey(k) }
func renderWGConfig(c core.TunnelConfig) string { return core.RenderWGConfig(c) }
func extractEmbedded(dest string, data []byte, want string) error {
	return core.ExtractEmbedded(dest, data, want)
}
func digestMatches(data []byte, want string) bool { return core.DigestMatches(data, want) }
