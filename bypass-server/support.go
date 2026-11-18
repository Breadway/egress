package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Support bundles uploaded by egress support --upload.
//
// Like install reports, this is diagnostic data rather than an authenticated
// channel: the public key identifies the device and anyone can claim one. The
// gate is that the key belongs to an enrolled device, plus a hard size cap and
// a short history, so an anonymous client cannot fill the disk and the admin
// still treats the contents as untrusted input.

const (
	supportBodyMax    = 2 << 20
	supportKeep       = 3
	supportPubHeader  = "X-Egress-Pubkey"
	supportVerHeader  = "X-Egress-Version"
	zipMagicFirstByte = 'P'
	zipMagicSecond    = 'K'
)

type supportUpload struct {
	Received string `json:"received"`
	Bytes    int    `json:"bytes"`
	Version  string `json:"version,omitempty"`
}

func (s *server) supportDir() string { return filepath.Join(s.state, "support") }

func (s *server) apiSupport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pub := strings.TrimSpace(r.Header.Get(supportPubHeader))
	if !validWireGuardKey(pub) {
		http.Error(w, "bad device key", http.StatusBadRequest)
		return
	}
	if !s.peerEnrolled(pub) {
		http.Error(w, "unknown device", http.StatusNotFound)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, supportBodyMax))
	if err != nil {
		http.Error(w, "bundle too large", http.StatusRequestEntityTooLarge)
		return
	}
	if len(data) < 4 || data[0] != zipMagicFirstByte || data[1] != zipMagicSecond {
		http.Error(w, "not a zip", http.StatusBadRequest)
		return
	}
	dir := s.supportDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		http.Error(w, "could not store", http.StatusInternalServerError)
		return
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	slug := reportSlug(pub)
	if err := os.WriteFile(filepath.Join(dir, slug+"-"+stamp+".zip"), data, 0600); err != nil {
		http.Error(w, "could not store", http.StatusInternalServerError)
		return
	}
	meta, _ := json.Marshal(supportUpload{
		Received: time.Now().UTC().Format(time.RFC3339),
		Bytes:    len(data),
		Version:  truncateText(r.Header.Get(supportVerHeader), 32),
	})
	_ = os.WriteFile(filepath.Join(dir, slug+"-"+stamp+".json"), meta, 0600)

	s.pruneSupport(slug)
	log.Printf("support: bundle from %s (%d bytes) stored as %s", shortKey(slug), len(data), slug+"-"+stamp+".zip")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "recorded")
}

// pruneSupport keeps the newest few bundles for one device.
func (s *server) pruneSupport(slug string) {
	matches, _ := filepath.Glob(filepath.Join(s.supportDir(), slug+"-*"))
	if len(matches) <= supportKeep*2 {
		return
	}
	// Glob sorts lexically and the timestamp sorts the same way.
	drop := matches[:len(matches)-supportKeep*2]
	for _, path := range drop {
		_ = os.Remove(path)
	}
}

// latestSupport returns the newest bundle for a device, if any.
func (s *server) latestSupport(pubkey string) (file string, meta supportUpload, ok bool) {
	slug := reportSlug(pubkey)
	zips, _ := filepath.Glob(filepath.Join(s.supportDir(), slug+"-*.zip"))
	if len(zips) == 0 {
		return "", supportUpload{}, false
	}
	file = zips[len(zips)-1]
	if data, err := os.ReadFile(strings.TrimSuffix(file, ".zip") + ".json"); err == nil {
		_ = json.Unmarshal(data, &meta)
	} else {
		if info, err := os.Stat(file); err == nil {
			meta = supportUpload{Received: info.ModTime().UTC().Format(time.RFC3339), Bytes: int(info.Size())}
		}
	}
	return file, meta, true
}

func shortKey(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}
