package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The desktop admin app uses these endpoints through the egress daemon. They
// are Bearer-token only and deliberately do not expose invite tokens, password
// hashes or claim hashes in list responses.

type adminCounts struct {
	Waiting     int `json:"waiting"`
	Ready       int `json:"ready"`
	Installed   int `json:"installed"`
	Attention   int `json:"attention"`
	Devices     int `json:"devices"`
	OpenInvites int `json:"open_invites"`
}

type adminApplicationRow struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Why             string `json:"why,omitempty"`
	OS              string `json:"os,omitempty"`
	Arch            string `json:"arch,omitempty"`
	Created         string `json:"created"`
	Reviewed        bool   `json:"reviewed"`
	State           string `json:"state"`
	DeviceID        string `json:"device_id,omitempty"`
	DeviceStatus    string `json:"device_status,omitempty"`
	ProvisionError  string `json:"provision_error,omitempty"`
	SetupDownloads  int    `json:"setup_downloads"`
	SetupDownloaded string `json:"setup_downloaded,omitempty"`
}

type adminDeviceRow struct {
	ID            string `json:"id"`
	Label         string `json:"label,omitempty"`
	Status        string `json:"status"`
	IP            string `json:"ip,omitempty"`
	Platform      string `json:"platform,omitempty"`
	Arch          string `json:"arch,omitempty"`
	Created       string `json:"created"`
	BoundAt       string `json:"bound_at,omitempty"`
	Expires       string `json:"expires,omitempty"`
	PubKey        string `json:"pubkey,omitempty"`
	RelayUser     string `json:"relay_user,omitempty"`
	ApplicationID string `json:"application_id,omitempty"`
}

func (s *server) adminJSONOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.bearerOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	f := s.loadFleet()
	waiting, ready, installed, attention := f.counts()
	bound, open := f.boundDevices()
	writeAdminJSON(w, struct {
		Counts       adminCounts           `json:"counts"`
		Applications []adminApplicationRow `json:"applications"`
	}{
		Counts: adminCounts{
			Waiting: waiting, Ready: ready, Installed: installed,
			Attention: attention, Devices: bound, OpenInvites: open,
		},
		Applications: adminApplicationRows(f),
	})
}

func (s *server) adminJSONApplications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.bearerOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeAdminJSON(w, struct {
		Applications []adminApplicationRow `json:"applications"`
	}{Applications: adminApplicationRows(s.loadFleet())})
}

func (s *server) adminJSONDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.bearerOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeAdminJSON(w, struct {
		Devices []adminDeviceRow `json:"devices"`
	}{Devices: adminDeviceRows(s.loadFleet())})
}

func adminApplicationRows(f *fleet) []adminApplicationRow {
	rows := make([]adminApplicationRow, 0, len(f.apps))
	for _, a := range f.apps {
		state, _ := f.appState(a)
		row := adminApplicationRow{
			ID: a.ID, Name: a.Name, Why: a.Why, OS: a.OS, Arch: a.Arch,
			Created: a.Created, Reviewed: a.Reviewed, State: state,
			DeviceID: a.DeviceID, ProvisionError: a.ProvisionError,
			SetupDownloads: a.SetupDownloads, SetupDownloaded: a.SetupDownloaded,
		}
		if d, ok := f.devByID[a.DeviceID]; ok {
			row.DeviceStatus = d.Status
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Created > rows[j].Created })
	return rows
}

func adminDeviceRows(f *fleet) []adminDeviceRow {
	rows := make([]adminDeviceRow, 0, len(f.devices))
	for _, d := range f.devices {
		row := adminDeviceRow{
			ID: d.ID, Label: d.Label, Status: d.Status, IP: d.IP,
			Platform: d.Platform, Arch: d.Arch, Created: d.Created,
			BoundAt: d.BoundAt, Expires: d.Expires, PubKey: d.PubKey,
			RelayUser: d.RelayUser,
		}
		if a, ok := f.deviceApp(d); ok {
			row.ApplicationID = a.ID
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Created > rows[j].Created })
	return rows
}

// adminJSONApplication performs an application action. Actions mirror the web
// admin: approve/prepare, reissue and delete.
func (s *server) adminJSONApplication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.bearerOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if !validID.MatchString(id) {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")

	s.appsMu.Lock()
	app, ok := s.applicationByID(id)
	if !ok {
		s.appsMu.Unlock()
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	switch action {
	case "approve", "reissue":
		if action == "approve" && app.DeviceID != "" {
			s.appsMu.Unlock()
			http.Error(w, "already prepared", http.StatusConflict)
			return
		}
		app.Reviewed = true
		app.ClaimedAt = ""
		app.ProvisionError = ""
		var err error
		if action == "reissue" {
			err = s.reissueApplication(&app)
		} else {
			err = s.provisionApplication(&app)
		}
		if err != nil {
			app.ProvisionError = truncateText(err.Error(), 300)
		}
	case "delete":
		s.appsMu.Unlock()
		if err := os.Remove(filepath.Join(s.state, "applications", id+".json")); err != nil && !os.IsNotExist(err) {
			http.Error(w, "could not delete", http.StatusInternalServerError)
			return
		}
		writeAdminJSON(w, map[string]bool{"ok": true})
		return
	default:
		s.appsMu.Unlock()
		http.Error(w, "bad action", http.StatusBadRequest)
		return
	}
	err := s.saveApplication(&app)
	s.appsMu.Unlock()
	if err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	writeAdminJSON(w, map[string]any{"ok": true, "id": app.ID, "state": func() string {
		st, _ := s.loadFleet().appState(app)
		return st
	}()})
}

// revokePeerForDevice is a variable so tests can avoid the root helper.
var revokePeerForDevice = revokePeer

// revokeDevice removes a bound device's access. The WireGuard peer goes first;
// if that fails the device stays so the operator can retry instead of
// believing access was revoked. Relay credentials are deleted after the peer.
func (s *server) revokeDevice(d device) error {
	if d.Status == "bound" && d.PubKey != "" {
		if err := revokePeerForDevice(d.PubKey); err != nil {
			return fmt.Errorf("remove WireGuard peer: %w", err)
		}
	}
	if d.RelayUser != "" {
		users, err := readRelayAuth(relayAuthFilePath())
		if err != nil {
			log.Printf("revoke %s: relay auth not readable: %v", d.ID, err)
		} else if _, ok := users[d.RelayUser]; ok {
			delete(users, d.RelayUser)
			if err := writeRelayAuth(relayAuthFilePath(), users); err != nil {
				log.Printf("revoke %s: relay auth not saved: %v", d.ID, err)
			}
		}
	}
	return nil
}

// adminJSONDevice creates or revokes an invite or bound device. The created
// token is returned once, exactly like the web page.
func (s *server) adminJSONDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.bearerOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")

	s.devicesMu.Lock()
	defer s.devicesMu.Unlock()
	reg, err := loadDevices(s.devicesPath())
	if err != nil {
		http.Error(w, "could not read devices", http.StatusInternalServerError)
		return
	}
	switch action {
	case "invite":
		token, terr := newToken()
		if terr != nil {
			http.Error(w, "could not create a token", http.StatusInternalServerError)
			return
		}
		raw := make([]byte, 4)
		_, _ = rand.Read(raw)
		label := strings.TrimSpace(r.FormValue("label"))
		if label == "" {
			label = "unlabelled"
		}
		now := time.Now().UTC()
		d := device{
			ID: "d-" + hex.EncodeToString(raw), Label: label,
			TokenHash: hashToken(token), Status: "issued",
			Created: now.Format(time.RFC3339),
			Expires: now.Add(enrollValidHours * time.Hour).Format(time.RFC3339),
		}
		reg.Devices = append(reg.Devices, d)
		if err := saveDevices(s.devicesPath(), reg); err != nil {
			http.Error(w, "could not save the invite", http.StatusInternalServerError)
			return
		}
		writeAdminJSON(w, map[string]any{"ok": true, "id": d.ID, "label": label, "token": token, "expires": d.Expires})
	case "revoke":
		id := strings.TrimSpace(r.FormValue("id"))
		var target *device
		for i := range reg.Devices {
			if reg.Devices[i].ID == id {
				target = &reg.Devices[i]
				break
			}
		}
		if target == nil {
			http.Error(w, "no device with that id", http.StatusNotFound)
			return
		}
		if err := s.revokeDevice(*target); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		kept := reg.Devices[:0]
		for _, d := range reg.Devices {
			if d.ID != id {
				kept = append(kept, d)
			}
		}
		reg.Devices = kept
		if err := saveDevices(s.devicesPath(), reg); err != nil {
			http.Error(w, "could not save", http.StatusInternalServerError)
			return
		}
		writeAdminJSON(w, map[string]bool{"ok": true})
	default:
		http.Error(w, "bad action", http.StatusBadRequest)
	}
}

func writeAdminJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
