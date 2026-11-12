package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testServer(t *testing.T) (*server, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "manifests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema":1,"version":"0.3.0"}`
	if err := os.WriteFile(filepath.Join(dir, "manifests", "linux-amd64.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	sum := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(dir, "blobs", sum), []byte("binary"), 0644); err != nil {
		t.Fatal(err)
	}
	return &server{dir: dir}, sum
}

func TestManifestAndBlob(t *testing.T) {
	s, sum := testServer(t)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/manifest?os=linux&arch=amd64", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "0.3.0") {
		t.Fatalf("manifest: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/blob/"+sum, nil))
	if w.Code != http.StatusOK || w.Body.String() != "binary" {
		t.Fatalf("blob: %d %q", w.Code, w.Body.String())
	}
}

func TestRejectsBadInput(t *testing.T) {
	s, _ := testServer(t)
	cases := []string{
		"/manifest?os=linux&arch=../../etc",
		"/manifest?os=&arch=amd64",
		"/blob/notahash",
		"/blob/" + strings.Repeat("b", 63),
	}
	for _, path := range cases {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusOK {
			t.Errorf("accepted %q", path)
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/manifest?os=linux&arch=amd64", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
}
