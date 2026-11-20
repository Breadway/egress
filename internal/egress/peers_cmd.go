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

	user, pass, ok := readAuthFile(filepath.Join(core.InstallDir(), "socks-auth"))
	if !ok || user == "" || pass == "" {
		return errors.New("this device has no relay credential, so the peer list cannot be authenticated")
	}
	req, err := http.NewRequest(http.MethodGet, "https://bypass.breadway.dev/api/peers", nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(user, pass)
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
			Label  string `json:"label"`
			PubKey string `json:"pubkey"`
			IP     string `json:"ip"`
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
	for _, peer := range payload.Peers {
		state := "unreachable"
		if plat.Ping(peer.IP) {
			state = "reachable"
		}
		label := peer.Label
		if label == "" {
			label = peer.PubKey[:min(10, len(peer.PubKey))]
		}
		fmt.Printf("%-10s %-14s %s\n", peer.IP, state, label)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
