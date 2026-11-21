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

// StateDir is where per-device state lives. EGRESS_STATE_DIR overrides it so a
// test or a second identity on one host can keep its own device key, relay key
// and credential without touching the installed state.
func StateDir() string {
	if dir := os.Getenv("EGRESS_STATE_DIR"); dir != "" {
		return dir
	}
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("ProgramData"); dir != "" {
			return filepath.Join(dir, "egress")
		}
		return `C:\ProgramData\egress`
	}
	if runtime.GOOS == "linux" {
		return "/var/lib/egress"
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "egress")
	}
	return "."
}

// CredentialPath is where the relay credential lives. It is a secret, so it
// does not belong in the binary directory even though older installs put it
// there; those are still read as a fallback.
func CredentialPath() string {
	if runtime.GOOS == "linux" || os.Getenv("EGRESS_STATE_DIR") != "" {
		return filepath.Join(StateDir(), "socks-auth")
	}
	return filepath.Join(InstallDir(), "socks-auth")
}

// DeviceIdentityPath is the non-secret half of the tunnel identity. It is state,
// not install payload, so it lives beside the other per-device state rather
// than in the binary directory.
func DeviceIdentityPath() string {
	return filepath.Join(StateDir(), "device.json")
}
