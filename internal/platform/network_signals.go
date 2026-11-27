package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"time"
)

// NetworkSignals is the raw, unhashed picture of the current network. It is
// consumed by internal/netid, which hashes each value before storing or
// sending anything.
type NetworkSignals struct {
	SSID         string
	DNSSuffix    string
	GatewayMAC   string
	DHCPServer   string
	Subnet       string
	Captive      string
	DNSResolvers []string
	GatewayIP    string
}

// interfaceSubnet returns the interface's IPv4 network in CIDR form.
func interfaceSubnet(iface string) string {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return ""
	}
	return subnetForInterface(i)
}

func subnetForInterface(i *net.Interface) string {
	addrs, err := i.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		return (&net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}).String()
	}
	return ""
}

// portalProbeURL is a captive-portal detector. The response is hashed, not
// stored, so a network that intercepts it gets a different fingerprint.
const portalProbeURL = "http://connectivitycheck.gstatic.com/generate_204"

// captiveFingerprint hashes an intercepted portal response. A clean 204 means
// there is no portal and returns empty: every clean network would otherwise
// share one hash and contribute a meaningless weight. The response is hashed,
// not stored, so a network that rewrites the probe gets a different value.
func captiveFingerprint() string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(portalProbeURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	sum := sha256.Sum256([]byte(resp.Status + "\n" + resp.Header.Get("Location") + "\n" + string(body)))
	return hex.EncodeToString(sum[:])[:32]
}
