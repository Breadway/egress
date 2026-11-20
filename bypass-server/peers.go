package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
)

// apiPeers returns the devices a client may reach over the tunnel.
//
// It is authenticated with the device's relay credential rather than left
// public: the response names every peer's tunnel address, which is not
// something to hand to an unauthenticated caller. The relationship model is
// deliberately minimal for now, a single circle, and a device without a circle
// is in it.
func (s *server) apiPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok || !validRelayCredential(user, pass) {
		w.Header().Set("WWW-Authenticate", `Basic realm="egress"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	type device struct {
		Label  string `json:"label"`
		PubKey string `json:"pubkey"`
		IP     string `json:"ip"`
		Status string `json:"status"`
		Circle string `json:"circle"`
	}
	var state struct {
		Devices []device `json:"devices"`
	}
	data, err := os.ReadFile(filepath.Join(s.state, "devices.json"))
	if err != nil {
		http.Error(w, "device registry unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := json.Unmarshal(data, &state); err != nil {
		http.Error(w, "device registry unreadable", http.StatusServiceUnavailable)
		return
	}

	endpoints := loadEndpoints()
	type peer struct {
		Label    string `json:"label"`
		PubKey   string `json:"pubkey"`
		IP       string `json:"ip"`
		Endpoint string `json:"endpoint,omitempty"`
	}
	peers := make([]peer, 0, len(state.Devices))
	for _, d := range state.Devices {
		if d.Status != "bound" || d.PubKey == "" || d.IP == "" {
			continue
		}
		if d.Circle != "" && d.Circle != "bread" {
			continue
		}
		peers = append(peers, peer{Label: d.Label, PubKey: d.PubKey, IP: d.IP, Endpoint: endpoints[d.PubKey]})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].IP < peers[j].IP })

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Peers []peer `json:"peers"`
	}{Peers: peers})
}

// loadEndpoints reads the map Aegis publishes from the live WireGuard
// endpoints. Missing or stale data simply means no direct attempt is offered.
func loadEndpoints() map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile("/var/lib/bypass/endpoints.json")
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, &out)
	return out
}

func validRelayCredential(user, pass string) bool {
	users, err := readRelayAuth(relayAuthPath)
	if err != nil {
		return false
	}
	want, ok := users[user]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(pass)) == 1
}
