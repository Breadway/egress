package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Enrollment binds this device to a one-time token. The device generates its
// own keypair; only the public key is sent, and the token stops working here.

type enrollCredentials struct {
	Device      string `json:"device"`
	IP          string `json:"ip"`
	RelayUser   string `json:"relay_user"`
	RelayPass   string `json:"relay_pass"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

const defaultEnrollServer = "https://bypass.breadway.dev"

// findEnrollToken resolves the token from the flag, the environment, or a
// one-line enroll.txt beside the executable. The file makes a downloaded
// installer a single right-click for the recipient.
func findEnrollToken(flagValue string) string {
	if t := strings.TrimSpace(flagValue); t != "" {
		return t
	}
	if t := strings.TrimSpace(os.Getenv("EGRESS_ENROLL_TOKEN")); t != "" {
		return t
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return readTokenFile(filepath.Join(filepath.Dir(exe), "enroll.txt"))
}

// readTokenFile returns the first non-empty, non-comment line.
func readTokenFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return ""
}

// enrollDevice exchanges a token and a public key for an address and relay
// credential. The private key never leaves this machine.
func enrollDevice(ctx context.Context, server, token, pubKey, label string) (enrollCredentials, error) {
	var out enrollCredentials
	base := strings.TrimRight(server, "/")
	if base == "" {
		base = defaultEnrollServer
	}
	body, err := json.Marshal(map[string]string{
		"token":    token,
		"pubkey":   pubKey,
		"platform": runtime.GOOS,
		"arch":     runtime.GOARCH,
		"label":    enrollLabel(label),
	})
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/enroll", strings.NewReader(string(body)))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return out, fmt.Errorf("enrollment refused: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&out); err != nil {
		return out, fmt.Errorf("unreadable enrollment response: %w", err)
	}
	if out.IP == "" {
		return out, errors.New("enrollment returned no address")
	}
	return out, nil
}

// Relay credentials are only needed by the Windows split proxy; empty values
// are fine elsewhere.
func (c enrollCredentials) hasRelay() bool {
	return c.RelayUser != "" && c.RelayPass != ""
}

// enrollLabel keeps a hostname under the server's limit.
func enrollLabel(label string) string {
	if len(label) > 64 {
		return label[:64]
	}
	return label
}
