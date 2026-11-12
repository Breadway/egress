package egress

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func validIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// resolveKey prefers an explicit flag, then the key compiled in at build time,
// then a prompt.
func resolveKey(flagKey, flagFile string) (string, error) {
	if strings.TrimSpace(flagKey) != "" {
		return normalizeKey(flagKey)
	}
	if flagFile != "" {
		data, err := os.ReadFile(flagFile)
		if err != nil {
			return "", err
		}
		return normalizeKey(string(data))
	}
	if embeddedKey != "" {
		return normalizeKey(embeddedKey)
	}
	fmt.Fprint(os.Stderr, "WireGuard private key: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no key provided: %w", err)
	}
	return normalizeKey(line)
}

func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not start listening: %w", addr, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
