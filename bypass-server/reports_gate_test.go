package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func reportTestServer(t *testing.T, peers ...string) *server {
	t.Helper()
	state := t.TempDir()
	for _, dir := range []string{state, filepath.Join(state, "applications"), filepath.Join(state, "binaries")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	users := map[string]user{}
	for i, peer := range peers {
		name := string(rune('a'+i)) + "user"
		users[name] = user{Hash: "x", Binary: "b", Label: "l", Peer: peer, Created: "t"}
	}
	data, _ := json.Marshal(users)
	if err := os.WriteFile(filepath.Join(state, "users.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return &server{
		state: state, token: "test-token",
		fails: map[string][]time.Time{}, applys: map[string][]time.Time{},
		reports: map[string][]time.Time{},
	}
}

func postReport(t *testing.T, s *server, pubkey string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"pubkey":` + strconv.Quote(pubkey) + `,"status":"functional","checks":{},"ts":"2026-01-01T00:00:00Z"}`
	r := httptest.NewRequest(http.MethodPost, "/api/report", strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	s.apiReport(w, r)
	return w
}

// TestReportRequiresEnrollment proves anonymous clients can neither poison
// a device's health nor fill the disk with fresh keys.
func TestReportRequiresEnrollment(t *testing.T) {
	const enrolled = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const stranger = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	s := reportTestServer(t, enrolled)

	if w := postReport(t, s, stranger); w.Code != http.StatusNotFound {
		t.Fatalf("unknown pubkey = %d, want 404", w.Code)
	}
	if w := postReport(t, s, "not-a-key"); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed pubkey = %d, want 400", w.Code)
	}
	if w := postReport(t, s, enrolled); w.Code != http.StatusAccepted {
		t.Fatalf("enrolled pubkey = %d, want 202", w.Code)
	}
}

// TestPruneReportsCapsDirectory proves the reports directory cannot grow
// without bound.
func TestPruneReportsCapsDirectory(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		name := filepath.Join(dir, string(rune('a'+i))+".json")
		if err := os.WriteFile(name, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		// Distinct mtimes, oldest first.
		old := time.Now().Add(-time.Duration(10-i) * time.Hour)
		if err := os.Chtimes(name, old, old); err != nil {
			t.Fatal(err)
		}
	}
	pruneReports(dir, 4)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 4 {
		t.Fatalf("files = %d, want 4", len(entries))
	}
	for _, want := range []string{"g.json", "h.json", "i.json", "j.json"} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("newest file %s should survive pruning", want)
		}
	}
}

// TestBucketsEvicted proves idle rate-limit entries disappear instead of
// accumulating per source address forever.
func TestBucketsEvicted(t *testing.T) {
	s := &server{
		fails: map[string][]time.Time{}, applys: map[string][]time.Time{},
		reports: map[string][]time.Time{},
	}
	stale := time.Now().Add(-2 * time.Hour)
	s.reports["10.0.0.9"] = []time.Time{stale}
	if !s.allow(s.reports, "10.0.0.1", reportRateMax, reportRateWindow) {
		t.Fatal("fresh source must be allowed")
	}
	if _, ok := s.reports["10.0.0.9"]; ok {
		t.Error("stale bucket must be evicted on the next allow call")
	}
}

// TestReportAcceptedForEnrolledDevice covers the enrollment path: a device
// that bound through /api/enroll is known only to devices.json, and its
// reports used to be rejected as "unknown device".
func TestReportAcceptedForEnrolledDevice(t *testing.T) {
	const bound = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	const issued = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
	s := reportTestServer(t)

	reg := deviceRegistry{
		Version: 1,
		Devices: []device{
			{ID: "d-11111111", Label: "vm", TokenHash: "x", Status: "bound", Created: "t", PubKey: bound, IP: "10.88.0.25"},
			{ID: "d-22222222", Label: "invite", TokenHash: "y", Status: "issued", Created: "t"},
		},
	}
	if err := saveDevices(s.devicesPath(), reg); err != nil {
		t.Fatal(err)
	}

	if w := postReport(t, s, bound); w.Code != http.StatusAccepted {
		t.Fatalf("bound device report = %d, want 202 (%s)", w.Code, w.Body.String())
	}
	if w := postReport(t, s, issued); w.Code != http.StatusNotFound {
		t.Fatalf("issued device report = %d, want 404", w.Code)
	}
}
