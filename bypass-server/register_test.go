package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testRegisterServer(t *testing.T, state string) *server {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(state, "binaries"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "binaries", "egress-test.exe"), []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}
	return &server{
		state: state, token: "test-token",
		fails: map[string][]time.Time{}, applys: map[string][]time.Time{},
		reports: map[string][]time.Time{},
	}
}

func registerForm(username, peer string) *http.Request {
	form := url.Values{
		"username": {username},
		"password": {"long-enough-password-1"},
		"label":    {"test device"},
		"binary":   {"egress-test.exe"},
		"os":       {"windows"},
		"arch":     {"amd64"},
		"peer":     {peer},
	}
	r := httptest.NewRequest(http.MethodPost, "/admin/api/users", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer test-token")
	return r
}

// TestRegisterRejectsOverwrite proves re-registering a username is a 409 that
// keeps the original peer: silently replacing the row used to orphan a live
// WireGuard peer with full access.
func TestRegisterRejectsOverwrite(t *testing.T) {
	s := testRegisterServer(t, t.TempDir())
	firstPeer := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	secondPeer := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

	w1 := httptest.NewRecorder()
	s.adminAddUser(w1, registerForm("testuser", firstPeer))
	if w1.Code != http.StatusCreated {
		t.Fatalf("first registration = %d, want 201 (%s)", w1.Code, w1.Body.String())
	}

	w2 := httptest.NewRecorder()
	s.adminAddUser(w2, registerForm("testuser", secondPeer))
	if w2.Code != http.StatusConflict {
		t.Fatalf("second registration = %d, want 409 (%s)", w2.Code, w2.Body.String())
	}

	users := s.loadUsers()
	u, ok := users["testuser"]
	if !ok {
		t.Fatal("original login vanished after rejected overwrite")
	}
	if u.Peer != firstPeer {
		t.Errorf("peer = %q, want original %q; overwrite must not rotate the row", u.Peer, firstPeer)
	}
	if u.Downloads != 0 {
		t.Errorf("downloads = %d, want 0; rejected overwrite must not reset counters", u.Downloads)
	}
}
