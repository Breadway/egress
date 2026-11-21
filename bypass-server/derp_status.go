package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// DerpStatus is the relay state a device reports about itself. It exists so the
// admin side can tell "no peer asked for the relay" from "the relay dial
// failed" without access to the device's log.
type DerpStatus struct {
	Device    string `json:"device"`
	Label     string `json:"label"`
	Connected bool   `json:"connected"`
	Relay     string `json:"relay,omitempty"`
	Region    string `json:"region,omitempty"`
	Peers     int    `json:"peers"`
	LastError string `json:"last_error,omitempty"`
	Version   string `json:"version,omitempty"`
	Updated   string `json:"updated"`
}

var derpStatusMu sync.Mutex

func (s *server) derpStatusPath() string { return filepath.Join(s.state, "derp_status.json") }

func loadDerpStatus(path string) (map[string]DerpStatus, error) {
	out := map[string]DerpStatus{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	return out, json.Unmarshal(data, &out)
}

func saveDerpStatus(path string, statuses map[string]DerpStatus) error {
	data, err := json.MarshalIndent(statuses, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

// apiDerpStatus records the caller's relay state, or lists the circle's state.
func (s *server) apiDerpStatus(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.callerDevice(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="egress"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var in struct {
			Connected bool   `json:"connected"`
			Relay     string `json:"relay"`
			Region    string `json:"region"`
			Peers     int    `json:"peers"`
			LastError string `json:"last_error"`
			Version   string `json:"version"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		derpStatusMu.Lock()
		defer derpStatusMu.Unlock()
		all, err := loadDerpStatus(s.derpStatusPath())
		if err != nil {
			http.Error(w, "status registry unavailable", http.StatusServiceUnavailable)
			return
		}
		all[dev.ID] = DerpStatus{
			Device: dev.ID, Label: dev.Label, Connected: in.Connected,
			Relay: in.Relay, Region: in.Region, Peers: in.Peers,
			LastError: in.LastError, Version: in.Version,
			Updated: time.Now().UTC().Format(time.RFC3339),
		}
		if err := saveDerpStatus(s.derpStatusPath(), all); err != nil {
			http.Error(w, "could not save relay status", http.StatusInternalServerError)
			return
		}
		writeJSON(w, struct {
			OK bool `json:"ok"`
		}{OK: true})
	case http.MethodGet:
		circle, ok := s.callerCircle(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		devices, err := loadDevices(s.devicesPath())
		if err != nil {
			http.Error(w, "device registry unavailable", http.StatusServiceUnavailable)
			return
		}
		inCircle := map[string]bool{}
		for _, d := range devices.Devices {
			if d.Status == "bound" && circleOf(d) == circle {
				inCircle[d.ID] = true
			}
		}
		derpStatusMu.Lock()
		defer derpStatusMu.Unlock()
		all, err := loadDerpStatus(s.derpStatusPath())
		if err != nil {
			http.Error(w, "status registry unavailable", http.StatusServiceUnavailable)
			return
		}
		out := make([]DerpStatus, 0, len(all))
		for _, st := range all {
			if inCircle[st.Device] {
				out = append(out, st)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Device < out[j].Device })
		writeJSON(w, struct {
			Devices []DerpStatus `json:"devices"`
		}{Devices: out})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
