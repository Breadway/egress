package egress

import (
	"egress/internal/split"
	"io"

	"egress/internal/core"
	"egress/internal/health"
	sysplatform "egress/internal/platform"
)

// The platform layer lives in internal/platform. These aliases keep the call
// sites in this package unchanged while the split is finished.
type platform = sysplatform.Interface

type Route = sysplatform.Route

func newPlatform() platform { return sysplatform.New() }

func installedBinaryPath() string             { return sysplatform.InstalledBinaryPath() }
func ensureInstalledBinary() (string, error)  { return sysplatform.EnsureInstalledBinary() }
func removeInstalledBinary()                  { sysplatform.RemoveInstalledBinary() }
func writeDiagnosePlatform(w io.Writer) error { return sysplatform.Diagnose(w) }

func checkWindowsSplit() string { return split.HealthCheck() }

func checkTunnelIdentity(p platform, tcfg core.TunnelConfig) error {
	return sysplatform.CheckTunnelIdentity(p, tcfg)
}

func logPath() string  { return sysplatform.LogPath() }
func spoolDir() string { return sysplatform.SpoolDir() }

func removeStaleFile(path string) { sysplatform.RemoveStaleFile(path) }

// init wires the identity writer to the platform's ACL-aware delete, so a file
// left unreadable by an earlier install can be replaced instead of silently
// losing the device identity.
func init() { health.RemoveStale = sysplatform.RemoveStaleFile }
