package split

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// NetworksFile is the SSID allowlist. An empty or missing file means "any
// network"; a non-empty file means the proxy only runs on a listed SSID.
func NetworksFile(dir string) string { return filepath.Join(dir, "networks.txt") }

// LoadNetworks reads the allowlist, lowercased, one SSID per line.
func LoadNetworks(dir string) []string {
	f, err := os.Open(NetworksFile(dir))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ssid := strings.TrimSpace(scanner.Text())
		if ssid == "" || strings.HasPrefix(ssid, "#") {
			continue
		}
		key := strings.ToLower(ssid)
		if !seen[key] {
			seen[key] = true
			out = append(out, ssid)
		}
	}
	return out
}

// SaveNetworks writes the allowlist atomically.
func SaveNetworks(dir string, ssids []string) error {
	if len(ssids) == 0 {
		err := os.Remove(NetworksFile(dir))
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# SSIDs egress may run on. Empty file or missing file means any.\n")
	for _, ssid := range ssids {
		b.WriteString(ssid + "\n")
	}
	path := NetworksFile(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// NetworkAllowed reports whether a network may run the client. An empty
// allowlist, or an SSID we could not read, never blocks: failing closed here
// would leave a laptop with no DNS.
func NetworkAllowed(dir, ssid string) bool {
	allowed := LoadNetworks(dir)
	if len(allowed) == 0 {
		return true
	}
	ssid = strings.ToLower(strings.TrimSpace(ssid))
	if ssid == "" {
		return true
	}
	for _, want := range allowed {
		if strings.ToLower(strings.TrimSpace(want)) == ssid {
			return true
		}
	}
	return false
}
