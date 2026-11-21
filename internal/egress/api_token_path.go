package egress

import (
	"os"
	"path/filepath"
	"runtime"
)

// apiTokenPath is where the daemon publishes the local GUI token. Linux uses
// the runtime directory, which is cleared at boot; the token itself is stable
// for the life of that file, and the GUI reads it at launch.
//
// The Tauri shell reads this exact path. EGRESS_API_TOKEN_FILE overrides it
// for tests and for a second identity on one host.
func apiTokenPath() string {
	if path := os.Getenv("EGRESS_API_TOKEN_FILE"); path != "" {
		return path
	}
	if runtime.GOOS == "linux" {
		return "/run/egress/api-token"
	}
	return filepath.Join(os.TempDir(), "egress-api-token")
}
