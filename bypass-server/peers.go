package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

// circleOf is the group a device belongs to. Devices created before circles
// existed have no field and are in "bread", so nothing has to be migrated.
func circleOf(d device) string {
	if d.Circle == "" {
		return "bread"
	}
	return d.Circle
}

// roleOf is the device's role. Missing means a person, so existing records do
// not have to be migrated.
func roleOf(d device) string {
	if d.Role == "" {
		return "person"
	}
	return d.Role
}

var circleRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// normalizeCircle keeps circle names to one readable form. An empty or invalid
// value falls back to the original circle rather than failing the save.
func normalizeCircle(raw string) string {
	c := strings.ToLower(strings.TrimSpace(raw))
	if c == "" {
		return "bread"
	}
	if !circleRe.MatchString(c) {
		return "bread"
	}
	return c
}

// apiPeers returns the devices a client may reach over the tunnel.
//
// It is authenticated: either with the device's relay credential, or with a
// bound device's public key for devices that do not hold a credential. The
// response names every peer's tunnel address and observed endpoint, so it is
// never anonymous. Peers are limited to the caller's circle.
func (s *server) apiPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	circle, role, ok := s.callerIdentity(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="egress"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	reg, err := loadDevices(s.devicesPath())
	if err != nil {
		http.Error(w, "device registry unavailable", http.StatusServiceUnavailable)
		return
	}

	endpoints := loadEndpoints()
	type peer struct {
		Label      string `json:"label"`
		PubKey     string `json:"pubkey"`
		IP         string `json:"ip"`
		Endpoint   string `json:"endpoint,omitempty"`
		DerpPubKey string `json:"derp_pubkey,omitempty"`
		Circle     string `json:"circle"`
		Role       string `json:"role,omitempty"`
	}
	peers := make([]peer, 0, len(reg.Devices))
	for _, d := range reg.Devices {
		if d.Status != "bound" || d.PubKey == "" || d.IP == "" {
			continue
		}
		if circleOf(d) != circle {
			continue
		}
		// Exit servers stay in the circle so they can serve it, but a person
		// should not see them as friends. An exit caller still sees everyone.
		if roleOf(d) == "exit" && role != "exit" {
			continue
		}
		peers = append(peers, peer{
			Label:      d.Label,
			PubKey:     d.PubKey,
			IP:         d.IP,
			Endpoint:   endpoints[d.PubKey],
			DerpPubKey: d.DerpPubKey,
			Circle:     circleOf(d),
			Role:       roleOf(d),
		})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].IP < peers[j].IP })

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Peers  []peer `json:"peers"`
		Circle string `json:"circle"`
	}{Peers: peers, Circle: circle})
}

// callerCircle authenticates the request and resolves the caller's circle. A
// valid relay credential whose device cannot be matched still counts as
// authenticated, in the default circle; the credential only ever exists for a
// bound device.
func (s *server) callerCircle(r *http.Request) (string, bool) {
	circle, _, ok := s.callerIdentity(r)
	return circle, ok
}

// callerIdentity authenticates the request and resolves the caller's circle
// and role. A valid relay credential whose device cannot be matched still
// counts as authenticated, as a person in the default circle; the credential
// only ever exists for a bound device.
func (s *server) callerIdentity(r *http.Request) (string, string, bool) {
	reg, err := loadDevices(s.devicesPath())
	if err != nil {
		return "", "", false
	}
	user, pass, ok := r.BasicAuth()
	if ok && validRelayCredential(user, pass) {
		for _, d := range reg.Devices {
			if d.Status == "bound" && d.RelayUser == user {
				return circleOf(d), roleOf(d), true
			}
		}
		return "bread", "person", true
	}
	key := strings.TrimSpace(r.URL.Query().Get("k"))
	if key == "" {
		return "", "", false
	}
	for _, d := range reg.Devices {
		if d.Status == "bound" && d.PubKey == key {
			return circleOf(d), roleOf(d), true
		}
	}
	return "", "", false
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
