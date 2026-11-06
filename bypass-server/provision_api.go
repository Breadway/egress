package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// pendingApp is the only application data the provisioner needs. The claim
// hash and the applicant's reason stay on the server.
type pendingApp struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Created string `json:"created"`
}

func (s *server) adminPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.bearerOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	now := time.Now()
	pending := make([]pendingApp, 0)
	for _, a := range s.loadApplications() {
		if !a.Reviewed || a.LinkedUser != "" || a.ProvisionError != "" {
			continue
		}
		if a.ClaimedAt != "" {
			if t, err := time.Parse(time.RFC3339, a.ClaimedAt); err == nil && now.Sub(t) < claimTTL {
				continue
			}
		}
		targetOS, targetArch := a.OS, a.Arch
		if targetOS == "" {
			targetOS, targetArch = "windows", "amd64"
		}
		if targetArch == "" {
			targetArch = "amd64"
		}
		pending = append(pending, pendingApp{ID: a.ID, Name: a.Name, OS: targetOS, Arch: targetArch, Created: a.Created})
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Created < pending[j].Created })
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(pending)
}

func (s *server) adminClaim(w http.ResponseWriter, r *http.Request) {
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
	id := r.FormValue("id")
	if !validID.MatchString(id) {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	s.appsMu.Lock()
	defer s.appsMu.Unlock()
	a, ok := s.applicationByID(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	now := time.Now()
	if !a.Reviewed || a.LinkedUser != "" || a.ProvisionError != "" {
		http.Error(w, "not claimable", http.StatusConflict)
		return
	}
	if a.ClaimedAt != "" {
		if t, err := time.Parse(time.RFC3339, a.ClaimedAt); err == nil && now.Sub(t) < claimTTL {
			http.Error(w, "already claimed", http.StatusConflict)
			return
		}
	}
	a.ClaimedAt = now.UTC().Format(time.RFC3339)
	if err := s.saveApplication(&a); err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	targetOS, targetArch := a.OS, a.Arch
	if targetOS == "" {
		targetOS, targetArch = "windows", "amd64"
	}
	if targetArch == "" {
		targetArch = "amd64"
	}
	_ = json.NewEncoder(w).Encode(pendingApp{ID: a.ID, Name: a.Name, OS: targetOS, Arch: targetArch, Created: a.Created})
}

// adminRelease clears a claim. A non-empty error parks the application so it
// stops retrying and shows up for a human; retrying clears it.
func (s *server) adminRelease(w http.ResponseWriter, r *http.Request) {
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
	id := r.FormValue("id")
	if !validID.MatchString(id) {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	s.appsMu.Lock()
	defer s.appsMu.Unlock()
	a, ok := s.applicationByID(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	a.ClaimedAt = ""
	if msg := strings.TrimSpace(r.FormValue("error")); msg != "" {
		a.ProvisionError = truncateText(msg, 300)
	}
	if err := s.saveApplication(&a); err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "released")
}

func (s *server) applicationByID(id string) (application, bool) {
	data, err := os.ReadFile(filepath.Join(s.state, "applications", id+".json"))
	if err != nil {
		return application{}, false
	}
	var a application
	if json.Unmarshal(data, &a) != nil {
		return application{}, false
	}
	return a, true
}

func truncateText(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) <= n {
		return v
	}
	return v[:n] + "..."
}
