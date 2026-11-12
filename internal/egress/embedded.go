package egress

import (
	"egress/internal/core"
	"os"
	"runtime"

	"egress/internal/wstunnel"
)

// wstunnelIsOurs reports whether path holds a copy this tool could have
// installed: the embedded digest for this build, or the pinned download
// digest for this platform. Anything else is the user's own copy that
// findWstunnel reused, and remove must leave it alone.
func wstunnelIsOurs(path, embeddedSHA string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if embeddedSHA != "" && core.DigestMatches(data, embeddedSHA) {
		return true
	}
	if sum := wstunnel.Sum(runtime.GOOS, runtime.GOARCH); sum != "" && core.DigestMatches(data, sum) {
		return true
	}
	return false
}
