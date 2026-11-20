package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A peer exit is a device in a circle that carries other members' blocked
// traffic. It is registered by the device itself, not by the admin, because
// only the device knows what port and path its relay is serving; the admin
// still controls who can see it by controlling the circle.
type peerExit struct {
	Device   string `json:"device"`
	Label    string `json:"label"`
	Endpoint string `json:"endpoint"`
	Path     string `json:"path"`
	PubKey   string `json:"pubkey"`
	Updated  string `json:"updated"`
}

type peerExitRegistry struct {
	Version int        `json:"version"`
	Exits   []peerExit `json:"exits"`
}

const peerExitMinInterval = 30 * time.Second

func (s *server) peerExitsPath() string { return filepath.Join(s.state, "peer_exits.json") }

func loadPeerExits(path string) (peerExitRegistry, error) {
	reg := peerExitRegistry{Version: 1}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return reg, nil
		}
		return reg, err
	}
	return reg, json.Unmarshal(data, &reg)
}

func savePeerExits(path string, reg peerExitRegistry) error {
	reg.Version = 1
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// apiExitAnnounce registers or withdraws a peer exit for the calling device.
func (s *server) apiExitAnnounce(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.callerDevice(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="egress"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if dev.PubKey == "" || dev.IP == "" {
		http.Error(w, "this device is not bound", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		s.devicesMu.Lock()
		defer s.devicesMu.Unlock()
		reg, err := loadPeerExits(s.peerExitsPath())
		if err != nil {
			http.Error(w, "exit registry unavailable", http.StatusServiceUnavailable)
			return
		}
		kept := reg.Exits[:0]
		for _, e := range reg.Exits {
			if e.Device != dev.ID {
				kept = append(kept, e)
			}
		}
		reg.Exits = kept
		if err := savePeerExits(s.peerExitsPath(), reg); err != nil {
			http.Error(w, "could not save the exit registry", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Endpoint string `json:"endpoint"`
		Path     string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	endpoint := strings.TrimSpace(req.Endpoint)
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || port == "" || strings.ContainsAny(host, " /") {
		http.Error(w, "endpoint must be host:port", http.StatusBadRequest)
		return
	}
	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = "/peer-exit"
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \r\n") {
		http.Error(w, "path must start with /", http.StatusBadRequest)
		return
	}

	s.devicesMu.Lock()
	defer s.devicesMu.Unlock()
	reg, err := loadPeerExits(s.peerExitsPath())
	if err != nil {
		http.Error(w, "exit registry unavailable", http.StatusServiceUnavailable)
		return
	}
	now := time.Now().UTC()
	replaced := false
	for i := range reg.Exits {
		if reg.Exits[i].Device != dev.ID {
			continue
		}
		reg.Exits[i] = peerExit{
			Device: dev.ID, Label: dev.Label, Endpoint: endpoint,
			Path: path, PubKey: dev.PubKey, Updated: now.Format(time.RFC3339),
		}
		replaced = true
		break
	}
	if !replaced {
		reg.Exits = append(reg.Exits, peerExit{
			Device: dev.ID, Label: dev.Label, Endpoint: endpoint,
			Path: path, PubKey: dev.PubKey, Updated: now.Format(time.RFC3339),
		})
	}
	if err := savePeerExits(s.peerExitsPath(), reg); err != nil {
		http.Error(w, "could not save the exit registry", http.StatusInternalServerError)
		return
	}
	writeJSON(w, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

// apiPeerExits lists the peer exits visible to the caller: same circle, not
// the caller itself. It is the sibling of /api/peers and uses the same auth.
func (s *server) apiPeerExits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	circle, ok := s.callerCircle(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="egress"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	self, _ := s.callerDevice(r)

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

	reg, err := loadPeerExits(s.peerExitsPath())
	if err != nil {
		http.Error(w, "exit registry unavailable", http.StatusServiceUnavailable)
		return
	}
	type entry struct {
		ID       string `json:"id"`
		Label    string `json:"label,omitempty"`
		Endpoint string `json:"endpoint"`
		Path     string `json:"path,omitempty"`
		PubKey   string `json:"pubkey"`
	}
	out := make([]entry, 0, len(reg.Exits))
	for _, e := range reg.Exits {
		if !inCircle[e.Device] || e.Device == self.ID {
			continue
		}
		out = append(out, entry{ID: e.Device, Label: e.Label, Endpoint: e.Endpoint, Path: e.Path, PubKey: e.PubKey})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, struct {
		Exits  []entry `json:"exits"`
		Circle string  `json:"circle"`
	}{Exits: out, Circle: circle})
}

// callerDevice resolves the authenticated device itself, which announcements
// need because they belong to one identity. A credential that does not map to
// a bound device is not enough to publish an exit.
func (s *server) callerDevice(r *http.Request) (device, bool) {
	reg, err := loadDevices(s.devicesPath())
	if err != nil {
		return device{}, false
	}
	if user, pass, ok := r.BasicAuth(); ok && validRelayCredential(user, pass) {
		for _, d := range reg.Devices {
			if d.Status == "bound" && d.RelayUser == user {
				return d, true
			}
		}
		return device{}, false
	}
	key := strings.TrimSpace(r.URL.Query().Get("k"))
	if key == "" {
		return device{}, false
	}
	for _, d := range reg.Devices {
		if d.Status == "bound" && d.PubKey == key {
			return d, true
		}
	}
	return device{}, false
}

// A use is a client saying "route my blocked traffic through this exit". The
// exit only adds a WireGuard peer for clients that asked, so it never hijacks
// the star route of a circle member that is not using it.
type exitUse struct {
	Client  string `json:"client"`
	Exit    string `json:"exit"`
	Updated string `json:"updated"`
}

type exitUseRegistry struct {
	Version int       `json:"version"`
	Uses    []exitUse `json:"uses"`
}

func (s *server) exitUsesPath() string { return filepath.Join(s.state, "peer_exit_uses.json") }

func loadExitUses(path string) (exitUseRegistry, error) {
	reg := exitUseRegistry{Version: 1}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return reg, nil
		}
		return reg, err
	}
	return reg, json.Unmarshal(data, &reg)
}

func saveExitUses(path string, reg exitUseRegistry) error {
	reg.Version = 1
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// apiExitUse records or withdraws the caller's choice of peer exit.
func (s *server) apiExitUse(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.callerDevice(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="egress"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.devicesMu.Lock()
	defer s.devicesMu.Unlock()
	uses, err := loadExitUses(s.exitUsesPath())
	if err != nil {
		http.Error(w, "exit registry unavailable", http.StatusServiceUnavailable)
		return
	}
	kept := uses.Uses[:0]
	for _, u := range uses.Uses {
		if u.Client != dev.ID {
			kept = append(kept, u)
		}
	}
	uses.Uses = kept

	if r.Method == http.MethodPost {
		var req struct {
			Exit string `json:"exit"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<10)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if !s.usableExit(dev, strings.TrimSpace(req.Exit)) {
			http.Error(w, "unknown exit", http.StatusBadRequest)
			return
		}
		uses.Uses = append(uses.Uses, exitUse{Client: dev.ID, Exit: strings.TrimSpace(req.Exit), Updated: time.Now().UTC().Format(time.RFC3339)})
	} else if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := saveExitUses(s.exitUsesPath(), uses); err != nil {
		http.Error(w, "could not save exit use", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

// usableExit reports whether the exit exists, is in the caller's circle, and is
// not the caller itself.
func (s *server) usableExit(caller device, exitID string) bool {
	if exitID == "" || exitID == caller.ID {
		return false
	}
	reg, err := loadPeerExits(s.peerExitsPath())
	if err != nil {
		return false
	}
	found := false
	for _, e := range reg.Exits {
		if e.Device == exitID {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	devices, err := loadDevices(s.devicesPath())
	if err != nil {
		return false
	}
	for _, d := range devices.Devices {
		if d.ID == exitID && d.Status == "bound" {
			return circleOf(d) == circleOf(caller)
		}
	}
	return false
}

// apiExitClients lists the devices using the caller as their exit. This is
// what the serving side polls to know which peers to add.
func (s *server) apiExitClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dev, ok := s.callerDevice(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="egress"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	uses, err := loadExitUses(s.exitUsesPath())
	if err != nil {
		http.Error(w, "exit registry unavailable", http.StatusServiceUnavailable)
		return
	}
	devices, err := loadDevices(s.devicesPath())
	if err != nil {
		http.Error(w, "device registry unavailable", http.StatusServiceUnavailable)
		return
	}
	type client struct {
		ID     string `json:"id"`
		Label  string `json:"label,omitempty"`
		IP     string `json:"ip"`
		PubKey string `json:"pubkey"`
	}
	out := make([]client, 0)
	for _, u := range uses.Uses {
		if u.Exit != dev.ID {
			continue
		}
		for _, d := range devices.Devices {
			if d.ID == u.Client && d.Status == "bound" && d.IP != "" && d.PubKey != "" {
				out = append(out, client{ID: d.ID, Label: d.Label, IP: d.IP, PubKey: d.PubKey})
				break
			}
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, struct {
		Clients []client `json:"clients"`
	}{Clients: out})
}
