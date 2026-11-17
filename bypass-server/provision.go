package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Approval now prepares the installer: an invite is issued automatically and
// the applicant's status page hands them a ready-to-run setup archive. No key
// is built per person and nothing has to be provisioned by hand.

const appCookieName = "bp_app"

func requestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// rememberApplication lets the browser reopen the status page without the
// secret link. The cookie holds the same claim the link does, is HttpOnly, and
// is scoped to this site.
func (s *server) rememberApplication(w http.ResponseWriter, r *http.Request, app *application, claim string) {
	http.SetCookie(w, &http.Cookie{
		Name:     appCookieName,
		Value:    app.ID + "." + claim,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   90 * 24 * 60 * 60,
	})
}

// applicationForRequest finds the application from the link or the cookie.
func (s *server) applicationForRequest(r *http.Request) (*application, bool) {
	if app, ok := s.loadApplication(r.URL.Query().Get("app"), r.URL.Query().Get("key")); ok {
		return app, true
	}
	cookie, err := r.Cookie(appCookieName)
	if err != nil {
		return nil, false
	}
	id, claim, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return nil, false
	}
	return s.loadApplication(id, claim)
}

// provisionApplication issues the device invite that the status page turns
// into a setup archive. Idempotent.
func (s *server) provisionApplication(app *application) error {
	if app.DeviceID != "" {
		return nil
	}
	if _, _, ok := s.genericInstaller(); !ok {
		return errors.New("no generic Windows installer in the binaries directory")
	}
	token, err := newToken()
	if err != nil {
		return err
	}
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	id := "d-" + hex.EncodeToString(raw)
	now := time.Now().UTC()
	s.devicesMu.Lock()
	reg, err := loadDevices(s.devicesPath())
	if err != nil {
		s.devicesMu.Unlock()
		return err
	}
	reg.Devices = append(reg.Devices, device{
		ID:        id,
		Label:     app.Name,
		TokenHash: hashToken(token),
		Status:    "issued",
		Created:   now.Format(time.RFC3339),
		Expires:   now.Add(enrollValidHours * time.Hour).Format(time.RFC3339),
	})
	err = saveDevices(s.devicesPath(), reg)
	s.devicesMu.Unlock()
	if err != nil {
		return err
	}
	app.DeviceID = id
	app.EnrollToken = token
	app.ProvisionedAt = now.Format(time.RFC3339)
	return nil
}

// genericInstaller is the shared Windows build that every approved applicant
// downloads. It carries no identity; the device enrolls on first run.
func (s *server) genericInstaller() (string, string, bool) {
	if p := strings.TrimSpace(os.Getenv("BYPASS_GENERIC_WINDOWS")); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, filepath.Base(p), true
		}
		return "", "", false
	}
	matches, _ := filepath.Glob(filepath.Join(s.state, "binaries", "egress-windows-amd64-*.exe"))
	if len(matches) == 0 {
		return "", "", false
	}
	sort.Slice(matches, func(i, j int) bool {
		ai, aerr := os.Stat(matches[i])
		bi, berr := os.Stat(matches[j])
		if aerr != nil || berr != nil {
			return matches[i] > matches[j]
		}
		return ai.ModTime().After(bi.ModTime())
	})
	return matches[0], filepath.Base(matches[0]), true
}

// setupArchive serves the installer, the one-time token and instructions as a
// single download, gated by the application's claim or cookie.
func (s *server) setupArchive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	name := strings.TrimPrefix(r.URL.Path, "/setup/")
	id := strings.TrimSuffix(name, ".zip")
	if !strings.HasSuffix(name, ".zip") || !validID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	app, ok := s.loadApplication(id, r.URL.Query().Get("key"))
	if !ok {
		if cookie, err := r.Cookie(appCookieName); err == nil {
			cid, claim, cut := strings.Cut(cookie.Value, ".")
			if cut && cid == id {
				app, ok = s.loadApplication(cid, claim)
			}
		}
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !app.Reviewed || app.DeviceID == "" || app.EnrollToken == "" {
		http.Error(w, "the installer is still being prepared", http.StatusConflict)
		return
	}
	exePath, _, ok := s.genericInstaller()
	if !ok {
		http.Error(w, "no installer is available right now", http.StatusServiceUnavailable)
		return
	}
	exe, err := os.ReadFile(exePath)
	if err != nil {
		http.Error(w, "could not read the installer", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	}
	if err := add("egress.exe", exe); err != nil {
		http.Error(w, "could not build the archive", http.StatusInternalServerError)
		return
	}
	if err := add("enroll.txt", []byte(app.EnrollToken+"\n")); err != nil {
		http.Error(w, "could not build the archive", http.StatusInternalServerError)
		return
	}
	instructions := fmt.Sprintf(`egress setup

1. Right-click egress.exe and choose "Run as administrator".
   If Windows shows "Windows protected your PC", click More info, then
   Run anyway.
2. Leave enroll.txt next to egress.exe. The installer reads it and binds
   this machine once.
3. Wait about a minute, then check the tray for the egress icon.

Token: %s
Application: %s

The token works once. If this install fails, ask for a new invite.
`, app.EnrollToken, app.Name)
	if err := add("README.txt", []byte(instructions)); err != nil {
		http.Error(w, "could not build the archive", http.StatusInternalServerError)
		return
	}
	if err := zw.Close(); err != nil {
		http.Error(w, "could not build the archive", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="egress-setup.zip"`)
	_, _ = w.Write(buf.Bytes())
}

// deviceStatuses maps a device id to its registry status.
func (s *server) deviceStatuses() map[string]string {
	out := map[string]string{}
	s.devicesMu.Lock()
	reg, err := loadDevices(s.devicesPath())
	s.devicesMu.Unlock()
	if err != nil {
		return out
	}
	for _, d := range reg.Devices {
		out[d.ID] = d.Status
	}
	return out
}

// deviceCounts returns bound and still-open invites.
func (s *server) deviceCounts() (bound, issued int) {
	s.devicesMu.Lock()
	reg, err := loadDevices(s.devicesPath())
	s.devicesMu.Unlock()
	if err != nil {
		return 0, 0
	}
	for _, d := range reg.Devices {
		if d.Status == "bound" {
			bound++
		} else {
			issued++
		}
	}
	return bound, issued
}
