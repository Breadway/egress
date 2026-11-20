package egress

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"egress/internal/core"
)

// cmdPeers lists the devices this one may reach over the tunnel and checks
// whether each answers. Traffic between them goes through Aegis today; direct
// links are the next step, and the list is the same either way.
func cmdPeers(args []string) error {
	fs := newFlagSet("peers")
	asJSON := fs.Bool("json", false, "print JSON")
	debug := fs.Bool("debug", false, "trace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))

	user, pass, ok := readAuthFile(core.CredentialPath())
	if !ok || user == "" || pass == "" {
		// Older Linux installs wrote the credential beside the binary.
		user, pass, ok = readAuthFile(filepath.Join(core.InstallDir(), "socks-auth"))
	}
	req, err := http.NewRequest(http.MethodGet, "https://bypass.breadway.dev/api/peers", nil)
	if err != nil {
		return err
	}
	if ok && user != "" && pass != "" {
		req.SetBasicAuth(user, pass)
	} else if self := devicePubkey(); self != "" {
		// A bound device's public key identifies it without a credential.
		q := req.URL.Query()
		q.Set("k", self)
		req.URL.RawQuery = q.Encode()
	} else {
		return errors.New("this device has neither a relay credential nor a device identity, so the peer list cannot be authenticated")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch peers: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch peers: %s", resp.Status)
	}
	var payload struct {
		Peers []struct {
			Label    string `json:"label"`
			PubKey   string `json:"pubkey"`
			IP       string `json:"ip"`
			Endpoint string `json:"endpoint"`
		} `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("read peers: %w", err)
	}
	sort.Slice(payload.Peers, func(i, j int) bool { return payload.Peers[i].IP < payload.Peers[j].IP })

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(payload)
	}
	if len(payload.Peers) == 0 {
		fmt.Println("no peers")
		return nil
	}
	plat := newPlatform()
	silent := false
	for _, peer := range payload.Peers {
		state := "no icmp reply"
		if plat.Ping(peer.IP) {
			state = "reachable"
		} else {
			silent = true
		}
		label := peer.Label
		if label == "" {
			label = peer.PubKey[:min(10, len(peer.PubKey))]
		}
		endpoint := peer.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}
		fmt.Printf("%-10s %-16s %-22s %s\n", peer.IP, state, endpoint, label)
	}
	if silent {
		fmt.Println("\nNo ICMP reply can mean the peer's firewall drops pings, not that it is down; Windows does by default.")
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
