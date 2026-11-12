package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testManifest(t *testing.T, priv ed25519.PrivateKey) UpdateManifest {
	t.Helper()
	m := UpdateManifest{
		Schema:   updateSchema,
		Version:  "0.3.0",
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		SHA256:   strings.Repeat("a", 64),
		Size:     1024,
		Released: "2026-11-12T00:00:00Z",
	}
	if err := SignUpdateManifest(&m, priv); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManifestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := testManifest(t, priv)
	if err := VerifyUpdateManifest(&m, pub, runtime.GOOS, runtime.GOARCH); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}

	tampered := m
	tampered.Version = "9.9.9"
	if err := VerifyUpdateManifest(&tampered, pub, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("tampered version accepted")
	}

	wrongTarget := m
	if err := VerifyUpdateManifest(&wrongTarget, pub, "plan9", runtime.GOARCH); err == nil {
		t.Fatal("manifest for another OS accepted")
	}

	badHash := m
	badHash.SHA256 = "not-a-hash"
	if err := VerifyUpdateManifest(&badHash, pub, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("bad hash accepted")
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyUpdateManifest(&m, otherPub, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("manifest accepted under the wrong key")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.2.0", "0.3.0", -1},
		{"0.3.0", "0.3.0", 0},
		{"0.10.0", "0.9.9", 1},
		{"v1.0.0", "1.0.0", 0},
	}
	for _, tc := range cases {
		got, err := CompareVersions(tc.a, tc.b)
		if err != nil || got != tc.want {
			t.Errorf("%s vs %s: got %d (%v), want %d", tc.a, tc.b, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "x.y.z", "1.2.3.4"} {
		if _, err := CompareVersions(bad, "1.0.0"); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestFetchUpdateManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := testManifest(t, priv)
	data, _ := json.Marshal(m)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/manifest" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	got, err := fetchUpdateManifest(context.Background(), srv.URL, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != m.Version {
		t.Fatalf("version: %q", got.Version)
	}

	// A server that swaps the payload must be rejected.
	bad, _ := json.Marshal(UpdateManifest{Schema: updateSchema, Version: "9.9.9", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: m.SHA256, Size: 1})
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bad) }))
	defer srv2.Close()
	if _, err := fetchUpdateManifest(context.Background(), srv2.URL, pub); err == nil {
		t.Fatal("unsigned manifest accepted")
	}
}

func TestParseWGConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")
	content := "[Interface]\nAddress = 10.88.0.2/32\nPrivateKey = cHJpdmF0ZWtleQ==\n\n[Peer]\nPublicKey = x\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	key, ip, err := parseWGConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if key != "cHJpdmF0ZWtleQ==" || ip != "10.88.0.2" {
		t.Fatalf("key=%q ip=%q", key, ip)
	}
	if _, _, err := parseWGConfigFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}
