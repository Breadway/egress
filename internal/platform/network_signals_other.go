//go:build !linux && !windows && !darwin

package platform

// ReadNetworkSignals is a best-effort fallback on unsupported platforms.
func ReadNetworkSignals(iface, gateway string) NetworkSignals {
	return NetworkSignals{
		GatewayIP: gateway,
		Subnet:    interfaceSubnet(iface),
		Captive:   captiveFingerprint(),
	}
}
