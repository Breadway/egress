package egress

import (
	"os"
	"path/filepath"
	"runtime"
)

// apiTokenPath is where the daemon publishes the local GUI token. Every path
// is readable by the signed-in user while the daemon still runs as root or
// SYSTEM:
//
//   - Linux: the runtime directory, cleared at boot.
//   - Windows: ProgramData\egress-gui, which inherits the Users read ACE from
//     ProgramData. The install directory is administrator-only, so it must not
//     be used here.
//   - macOS: the local var run directory.
//
// The Tauri shell resolves the same path. EGRESS_API_TOKEN_FILE overrides it
// for tests and for a second identity on one host.
func apiTokenPath() string {
	if path := os.Getenv("EGRESS_API_TOKEN_FILE"); path != "" {
		return path
	}
	switch runtime.GOOS {
	case "linux":
		return "/run/egress/api-token"
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "egress-gui", "api-token")
	default:
		return "/usr/local/var/run/egress/api-token"
	}
}
