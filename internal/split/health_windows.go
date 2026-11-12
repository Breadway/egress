//go:build windows

package split

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"egress/internal/core"
)

// ProxyListenAddr is the default loopback CONNECT proxy address.
const ProxyListenAddr = "127.0.0.1:1081"

// HealthCheck reports the Windows split client's state for install reports and
// verify: the proxy must accept connections and the PAC must exist.
func HealthCheck() string {
	if !ProxyListening() {
		return "proxy not listening on " + ProxyListenAddr
	}
	pac := filepath.Join(core.InstallDir(), "proxy.pac")
	if _, err := os.Stat(pac); err != nil {
		return "PAC missing at " + pac
	}
	return "ok"
}

// ProxyListening reports whether the local proxy accepts connections.
func ProxyListening() bool {
	c, err := net.DialTimeout("tcp", ProxyListenAddr, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// WaitForProxy blocks until the proxy binds after being started.
func WaitForProxy(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ProxyListening() {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("split proxy did not start on " + ProxyListenAddr)
}
