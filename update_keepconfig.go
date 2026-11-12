package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// parseWGConfigFile pulls the private key and client address out of an
// existing WireGuard config. Used by install --keep-config so an update can
// reuse the device identity instead of prompting for it.
func parseWGConfigFile(path string) (key, ip string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(name) {
		case "PrivateKey":
			key = strings.TrimSpace(value)
		case "Address":
			addr := strings.TrimSpace(value)
			if i := strings.Index(addr, ","); i >= 0 {
				addr = addr[:i]
			}
			if i := strings.Index(addr, "/"); i >= 0 {
				addr = addr[:i]
			}
			ip = strings.TrimSpace(addr)
		}
	}
	if key == "" {
		return "", "", errors.New("no PrivateKey in " + path)
	}
	if ip == "" {
		return "", "", errors.New("no Address in " + path)
	}
	return key, ip, nil
}

// existingTunnelConfig finds the installed config on this platform.
func existingTunnelConfig() (string, string, error) {
	var path string
	switch runtime.GOOS {
	case "linux":
		path = "/etc/wireguard/wg0.conf"
	case "windows":
		path = `C:\ProgramData\egress\wg0.conf`
	default:
		return "", "", fmt.Errorf("--keep-config is not supported on %s yet", runtime.GOOS)
	}
	return parseWGConfigFile(path)
}
