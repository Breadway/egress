//go:build windows

package split

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"egress/internal/core"
)

// ProxyListenAddr is the default loopback CONNECT proxy address.
const ProxyListenAddr = "127.0.0.1:1081"

// HealthCheck reports the Windows split client's state for install reports and
// verify: the proxy must accept connections, actually forward one, and the PAC
// must exist where the browser can read it.
func HealthCheck() string {
	if !ProxyListening() {
		return "proxy not listening on " + ProxyListenAddr
	}
	if !proxyReachesUpstream() {
		return "proxy is listening but cannot forward a CONNECT to an upstream"
	}
	pac := PACPath()
	if _, err := os.Stat(pac); err != nil {
		return "PAC missing at " + pac
	}
	return "ok"
}

// PACPath is where the PAC lives: the user's profile, because the install
// directory is locked to SYSTEM and Administrators and the browser runs as the
// user.
func PACPath() string { return filepath.Join(ProxyDir(), "proxy.pac") }

// proxyReachesUpstream opens a CONNECT tunnel through the local proxy. A
// listening port alone proves nothing, which is how a browser could report
// itself offline while verify passed.
func proxyReachesUpstream() bool {
	conn, err := net.DialTimeout("tcp", ProxyListenAddr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	target := core.ReportHost + ":443"
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return false
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.Contains(line, "200")
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
