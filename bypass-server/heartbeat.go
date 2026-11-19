package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Update check heartbeats. Reports carry the health of an install, but only on
// install, update or a manual command; a machine whose service is dead and
// whose updater is gone looks identical to one that is quietly working. The
// update check runs every minute, so its heartbeat is the liveness signal.

const heartbeatBodyMax = 4 << 10

type heartbeat struct {
	Last    string `json:"last"`
	Version string `json:"version,omitempty"`
	Latest  string `json:"latest,omitempty"`
	OS      string `json:"os,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

type heartbeatRequest struct {
	Pubkey  string `json:"pubkey"`
	Version string `json:"version"`
	Latest  string `json:"latest"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

func (s *server) heartbeatDir() string { return filepath.Join(s.state, "heartbeats") }

func (s *server) heartbeatPath(pubkey string) string {
	return filepath.Join(s.heartbeatDir(), reportSlug(pubkey)+".json")
}

func (s *server) apiHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req heartbeatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, heartbeatBodyMax)).Decode(&req); err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	if !validWireGuardKey(req.Pubkey) {
		http.Error(w, "bad device key", http.StatusBadRequest)
		return
	}
	if !s.peerEnrolled(req.Pubkey) {
		http.Error(w, "unknown device", http.StatusNotFound)
		return
	}
	if err := os.MkdirAll(s.heartbeatDir(), 0700); err != nil {
		http.Error(w, "could not store", http.StatusInternalServerError)
		return
	}
	hb := heartbeat{
		Last:    time.Now().UTC().Format(time.RFC3339),
		Version: truncateText(req.Version, 32),
		Latest:  truncateText(req.Latest, 32),
		OS:      truncateText(req.OS, 16),
		Arch:    truncateText(req.Arch, 16),
	}
	data, err := json.MarshalIndent(hb, "", "  ")
	if err != nil {
		http.Error(w, "could not store", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(s.heartbeatPath(req.Pubkey), data, 0600); err != nil {
		http.Error(w, "could not store", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// latestHeartbeat returns the last update check for a device, if any.
func (s *server) latestHeartbeat(pubkey string) (heartbeat, bool) {
	if pubkey == "" {
		return heartbeat{}, false
	}
	data, err := os.ReadFile(s.heartbeatPath(pubkey))
	if err != nil {
		return heartbeat{}, false
	}
	var hb heartbeat
	if json.Unmarshal(data, &hb) != nil {
		return heartbeat{}, false
	}
	return hb, true
}
