//go:build !linux && !windows && !darwin

package platform

// SSID is unavailable on this platform.
func SSID(string) string { return "" }
