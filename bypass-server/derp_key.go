package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// apiDerpKey records the caller's relay identity. The relay key is deliberately
// not the WireGuard key: the relay sees it and uses it as a routing address,
// while the WireGuard key authenticates the tunnel.
func (s *server) apiDerpKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dev, ok := s.callerDevice(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="egress"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		PubKey string `json:"pubkey"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.PubKey)
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 || !enrollPubKeyRe.MatchString(key) {
		http.Error(w, "pubkey must be a 32-byte base64 key", http.StatusBadRequest)
		return
	}

	s.devicesMu.Lock()
	defer s.devicesMu.Unlock()
	reg, err := loadDevices(s.devicesPath())
	if err != nil {
		http.Error(w, "device registry unavailable", http.StatusServiceUnavailable)
		return
	}
	changed := false
	for i := range reg.Devices {
		if reg.Devices[i].ID != dev.ID {
			continue
		}
		if reg.Devices[i].DerpPubKey != key {
			reg.Devices[i].DerpPubKey = key
			changed = true
		}
		break
	}
	if changed {
		if err := saveDevices(s.devicesPath(), reg); err != nil {
			http.Error(w, "could not save the relay key", http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, struct {
		OK bool `json:"ok"`
	}{OK: true})
}
