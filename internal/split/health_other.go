//go:build !windows

package split

// HealthCheck is empty off Windows: there is no per-user proxy to probe.
func HealthCheck() string { return "" }
