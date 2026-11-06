package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func claimTestServer(t *testing.T) *server {
	t.Helper()
	state := t.TempDir()
	for _, dir := range []string{state, filepath.Join(state, "applications"), filepath.Join(state, "binaries")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "binaries", "egress-test.exe"), []byte("installer-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef"
	app := application{
		ID: id, Name: "Claim Test", OS: "windows", Arch: "amd64",
		ClaimHash: hashClaim("secret-claim-key-0000000000000000"),
		Reviewed:  true, Created: time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(app, "", "  ")
	if err := os.WriteFile(filepath.Join(state, "applications", id+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return &server{
		state: state, token: "test-token",
		fails: map[string][]time.Time{}, applys: map[string][]time.Time{},
		reports: map[string][]time.Time{},
	}
}

func bearerPost(path string, form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer test-token")
	r.RemoteAddr = "127.0.0.1:1"
	return r
}

// TestClaimReleaseLifecycle proves the provisioner handoff: claim hides the
// app from pending, release with an error parks it, and a clean release
// makes it claimable again.
func TestClaimReleaseLifecycle(t *testing.T) {
	s := claimTestServer(t)
	id := "0123456789abcdef"

	w := httptest.NewRecorder()
	s.adminClaim(w, bearerPost("/admin/api/claim", url.Values{"id": {id}}))
	if w.Code != http.StatusOK {
		t.Fatalf("claim = %d, want 200 (%s)", w.Code, w.Body.String())
	}

	// Claimed apps disappear from pending while the claim is fresh.
	pr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/pending", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	req.RemoteAddr = "127.0.0.1:1"
	s.adminPending(pr, req)
	var pending []pendingApp
	if err := json.Unmarshal(pr.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	for _, p := range pending {
		if p.ID == id {
			t.Fatal("claimed app must not appear in pending")
		}
	}

	// Double claim conflicts.
	w2 := httptest.NewRecorder()
	s.adminClaim(w2, bearerPost("/admin/api/claim", url.Values{"id": {id}}))
	if w2.Code != http.StatusConflict {
		t.Fatalf("double claim = %d, want 409", w2.Code)
	}

	// Release with an error parks the app: still hidden from pending.
	w3 := httptest.NewRecorder()
	s.adminRelease(w3, bearerPost("/admin/api/release", url.Values{"id": {id}, "error": {"disk full"}}))
	if w3.Code != http.StatusOK {
		t.Fatalf("release = %d, want 200", w3.Code)
	}
	pr2 := httptest.NewRecorder()
	s.adminPending(pr2, req)
	pending = nil
	if err := json.Unmarshal(pr2.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	for _, p := range pending {
		if p.ID == id {
			t.Fatal("error-parked app must not appear in pending")
		}
	}

	// Clean release clears the claim but keeps the parked error: a human
	// Retry in the admin UI is what unparks it.
	w4 := httptest.NewRecorder()
	s.adminRelease(w4, bearerPost("/admin/api/release", url.Values{"id": {id}}))
	if w4.Code != http.StatusOK {
		t.Fatalf("clean release = %d, want 200", w4.Code)
	}
	app, ok := s.applicationByID(id)
	if !ok {
		t.Fatal("app vanished after release")
	}
	if app.ClaimedAt != "" {
		t.Errorf("after release claim=%q, want empty", app.ClaimedAt)
	}
	if app.ProvisionError != "disk full" {
		t.Errorf("after clean release error=%q, want parked error kept", app.ProvisionError)
	}
}

// TestDownloadAuth proves the installer download checks the bcrypt password
// and counts completed downloads.
func TestDownloadAuth(t *testing.T) {
	s := claimTestServer(t)
	password := "correct-horse-37-battery"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]user{
		"testuser": {
			Hash: string(hash), Password: password, Binary: "egress-test.exe",
			Label: "test", OS: "windows", Arch: "amd64",
			Created: time.Now().UTC().Format(time.RFC3339),
		},
	}
	if err := s.saveUsers(users); err != nil {
		t.Fatal(err)
	}

	good := httptest.NewRecorder()
	s.download(good, bearerPost("/download", url.Values{"username": {"testuser"}, "password": {password}}))
	if good.Code != http.StatusOK {
		t.Fatalf("good password = %d, want 200 (%s)", good.Code, good.Body.String())
	}
	if good.Body.String() != "installer-bytes" {
		t.Errorf("download body = %q, want installer bytes", good.Body.String())
	}

	bad := httptest.NewRecorder()
	s.download(bad, bearerPost("/download", url.Values{"username": {"testuser"}, "password": {"wrong-password-000"}}))
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad password = %d, want 401", bad.Code)
	}

	if got := s.loadUsers()["testuser"].Downloads; got != 1 {
		t.Errorf("downloads = %d, want 1 counted", got)
	}
}
