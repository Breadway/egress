//go:build !windows

package egress

// proxyNetworkAllowed is a no-op without a PAC: the Linux split controller
// gates on the tunnel itself.
func proxyNetworkAllowed() bool { return true }
