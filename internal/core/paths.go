package core

import (
	"os"
	"path/filepath"
	"runtime"
)

// InstallDir is where the binary and the bundled wstunnel live. It is
// platform state, not policy, so it sits in core where both the platform layer
// and the wstunnel helper can read it without importing each other.
func InstallDir() string {
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("ProgramData"); dir != "" {
			return filepath.Join(dir, "egress")
		}
		return `C:\ProgramData\egress`
	}
	return "/usr/local/bin"
}
