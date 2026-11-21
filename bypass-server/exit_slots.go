package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var exitSlotsMu sync.Mutex

// An exit slot is a per-client relay identity on an exit. One exit identity is
// one DERP connection, and a single connection tops out at roughly 21 Mbps, so
// each client gets its own slot and its own share of the exit's capacity.
type exitSlot struct {
	Exit     string `json:"exit"`
	Client   string `json:"client"`
	RelayKey string `json:"relay_key"`
	Updated  string `json:"updated"`
}

type exitSlotRegistry struct {
	Version int        `json:"version"`
	Slots   []exitSlot `json:"slots"`
}

func (s *server) exitSlotsPath() string { return filepath.Join(s.state, "peer_exit_slots.json") }

func loadExitSlots(path string) (exitSlotRegistry, error) {
	reg := exitSlotRegistry{Version: 1}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return reg, nil
		}
		return reg, err
	}
	return reg, json.Unmarshal(data, &reg)
}

func saveExitSlots(path string, reg exitSlotRegistry) error {
	reg.Version = 1
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// apiExitSlot registers the relay identity an exit created for one client.
func (s *server) apiExitSlot(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.callerDevice(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="egress"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.devicesMu.Lock()
	defer s.devicesMu.Unlock()
	exitSlotsMu.Lock()
	defer exitSlotsMu.Unlock()
	reg, err := loadExitSlots(s.exitSlotsPath())
	if err != nil {
		http.Error(w, "slot registry unavailable", http.StatusServiceUnavailable)
		return
	}

	if r.Method == http.MethodPost {
		var in struct {
			Client   string `json:"client"`
			RelayKey string `json:"relay_key"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		client := strings.TrimSpace(in.Client)
		key := strings.TrimSpace(in.RelayKey)
		if raw, kerr := base64.StdEncoding.DecodeString(key); kerr != nil || len(raw) != 32 {
			http.Error(w, "relay key must be 32 bytes of base64", http.StatusBadRequest)
			return
		}
		if !s.exitSlotAllowed(dev, client) {
			http.Error(w, "client is not using this exit", http.StatusBadRequest)
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		replaced := false
		for i := range reg.Slots {
			if reg.Slots[i].Exit == dev.ID && reg.Slots[i].Client == client {
				reg.Slots[i].RelayKey = key
				reg.Slots[i].Updated = now
				replaced = true
				break
			}
		}
		if !replaced {
			reg.Slots = append(reg.Slots, exitSlot{Exit: dev.ID, Client: client, RelayKey: key, Updated: now})
		}
	} else {
		client := strings.TrimSpace(r.URL.Query().Get("client"))
		kept := reg.Slots[:0]
		for _, slot := range reg.Slots {
			if slot.Exit == dev.ID && (client == "" || slot.Client == client) {
				continue
			}
			kept = append(kept, slot)
		}
		reg.Slots = kept
	}
	if err := saveExitSlots(s.exitSlotsPath(), reg); err != nil {
		http.Error(w, "could not save slot", http.StatusInternalServerError)
		return
	}
	writeJSON(w, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

// exitSlotAllowed checks that the caller is a registered exit and that the
// client is in its circle and currently using it.
func (s *server) exitSlotAllowed(exit device, clientID string) bool {
	if clientID == "" || clientID == exit.ID {
		return false
	}
	exits, err := loadPeerExits(s.peerExitsPath())
	if err != nil {
		return false
	}
	isExit := false
	for _, e := range exits.Exits {
		if e.Device == exit.ID && e.Transport == "derp" {
			isExit = true
			break
		}
	}
	if !isExit {
		return false
	}
	uses, err := loadExitUses(s.exitUsesPath())
	if err != nil {
		return false
	}
	using := false
	for _, u := range uses.Uses {
		if u.Client == clientID && u.Exit == exit.ID {
			using = true
			break
		}
	}
	if !using {
		return false
	}
	devices, err := loadDevices(s.devicesPath())
	if err != nil {
		return false
	}
	for _, d := range devices.Devices {
		if d.ID == clientID && d.Status == "bound" {
			return circleOf(d) == circleOf(exit)
		}
	}
	return false
}

// removeExitSlots drops slots matching a client or an exit. It is called when
// the relationship that justified them ends.
func (s *server) removeExitSlots(exitID, clientID string) {
	exitSlotsMu.Lock()
	defer exitSlotsMu.Unlock()
	reg, err := loadExitSlots(s.exitSlotsPath())
	if err != nil {
		return
	}
	kept := reg.Slots[:0]
	for _, slot := range reg.Slots {
		if (exitID != "" && slot.Exit == exitID) || (clientID != "" && slot.Client == clientID) {
			continue
		}
		kept = append(kept, slot)
	}
	if len(kept) == len(reg.Slots) {
		return
	}
	reg.Slots = kept
	_ = saveExitSlots(s.exitSlotsPath(), reg)
}

// removeClientSlotsExcept drops a client's slots on other exits when the
// client switches. Repeating a use of the same exit must not delete its slot.
func (s *server) removeClientSlotsExcept(clientID, keepExit string) {
	if clientID == "" {
		return
	}
	exitSlotsMu.Lock()
	defer exitSlotsMu.Unlock()
	reg, err := loadExitSlots(s.exitSlotsPath())
	if err != nil {
		return
	}
	kept := reg.Slots[:0]
	changed := false
	for _, slot := range reg.Slots {
		if slot.Client == clientID && slot.Exit != keepExit {
			changed = true
			continue
		}
		kept = append(kept, slot)
	}
	if !changed {
		return
	}
	reg.Slots = kept
	_ = saveExitSlots(s.exitSlotsPath(), reg)
}

// exitSlotMap returns the slots for a set of exits, keyed by exit then client.
func (s *server) exitSlotMap() map[[2]string]string {
	out := map[[2]string]string{}
	exitSlotsMu.Lock()
	defer exitSlotsMu.Unlock()
	reg, err := loadExitSlots(s.exitSlotsPath())
	if err != nil {
		return out
	}
	for _, slot := range reg.Slots {
		out[[2]string{slot.Exit, slot.Client}] = slot.RelayKey
	}
	return out
}

// sortedSlots is only used by tests and diagnostics.
func sortedSlots(reg exitSlotRegistry) []exitSlot {
	out := append([]exitSlot(nil), reg.Slots...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Exit != out[j].Exit {
			return out[i].Exit < out[j].Exit
		}
		return out[i].Client < out[j].Client
	})
	return out
}
