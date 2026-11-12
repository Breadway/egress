package egress

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"egress/internal/update"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testManifest(t *testing.T, priv ed25519.PrivateKey) update.Manifest {
	t.Helper()
	m := update.Manifest{
		Schema:   1,
		Version:  "0.3.0",
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		SHA256:   strings.Repeat("a", 64),
		Size:     1024,
		Released: "2026-11-12T00:00:00Z",
	}
	if err := update.Sign(&m, priv); err != nil {
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
	if err := update.Verify(&m, pub, runtime.GOOS, runtime.GOARCH); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}

	tampered := m
	tampered.Version = "9.9.9"
	if err := update.Verify(&tampered, pub, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("tampered version accepted")
	}

	wrongTarget := m
	if err := update.Verify(&wrongTarget, pub, "plan9", runtime.GOARCH); err == nil {
		t.Fatal("manifest for another OS accepted")
	}

	badHash := m
	badHash.SHA256 = "not-a-hash"
	if err := update.Verify(&badHash, pub, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("bad hash accepted")
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := update.Verify(&m, otherPub, runtime.GOOS, runtime.GOARCH); err == nil {
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
		got, err := update.CompareVersions(tc.a, tc.b)
		if err != nil || got != tc.want {
			t.Errorf("%s vs %s: got %d (%v), want %d", tc.a, tc.b, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "x.y.z", "1.2.3.4"} {
		if _, err := update.CompareVersions(bad, "1.0.0"); err == nil {
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
	bad, _ := json.Marshal(update.Manifest{Schema: 1, Version: "9.9.9", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: m.SHA256, Size: 1})
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

func TestBuildReportParkedIsFailed(t *testing.T) {
	results := checkResults{Tunnel: "skipped", Probe: "skipped"}
	data, err := buildReport(tunnelConfig{}, results, errors.New("split client setup failed"), true)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "failed" {
		t.Errorf("status = %v, want failed (a parked install is not healthy)", got["status"])
	}
	if got["parked"] != true {
		t.Errorf("parked = %v, want true", got["parked"])
	}

	ok, err := buildReport(tunnelConfig{}, results, nil, false)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	got = map[string]any{}
	if err := json.Unmarshal(ok, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] == "failed" {
		t.Errorf("clean install reported failed: %v", got["status"])
	}
	if _, present := got["parked"]; present {
		t.Errorf("clean install reported parked")
	}
}

func TestInstalledExePathOnLinux(t *testing.T) {
	path, err := installedExePath()
	if err != nil || path == "" {
		t.Fatalf("path=%q err=%v", path, err)
	}
}

func TestCheckManifestVersionRefusesDowngrade(t *testing.T) {
	older := update.Manifest{Version: "0.4.1"}
	if err := checkManifestVersion("0.4.9", older); err == nil {
		t.Fatal("a replayed older manifest was accepted")
	}
	older.Force = true
	if err := checkManifestVersion("0.4.9", older); err != nil {
		t.Fatalf("forced republish refused: %v", err)
	}
	same := update.Manifest{Version: "0.4.9"}
	if err := checkManifestVersion("0.4.9", same); err != nil {
		t.Fatalf("same version refused: %v", err)
	}
	newer := update.Manifest{Version: "0.5.0"}
	if err := checkManifestVersion("0.4.9", newer); err != nil {
		t.Fatalf("newer version refused: %v", err)
	}
}

// TestManifestFetchAndVerify runs the publisher half end to end: sign a
// manifest, serve it, fetch and verify it, then prove a tampered copy is
// rejected. It covers the contract the update path depends on without
// touching the filesystem or the service manager.
func TestManifestFetchAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := update.Manifest{
		Schema: 1, Version: "9.9.9", OS: runtime.GOOS, Arch: runtime.GOARCH,
		SHA256: strings.Repeat("ab", 32), Size: 12, Released: "2026-01-01T00:00:00Z",
	}
	if err := update.Sign(&m, priv); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(m)
	}))
	defer srv.Close()

	got, err := fetchUpdateManifest(context.Background(), srv.URL, pub)
	if err != nil {
		t.Fatalf("fetch/verify: %v", err)
	}
	if got.Version != m.Version {
		t.Fatalf("version: %q", got.Version)
	}

	// Tamper with the signed payload: verification must fail.
	tampered := m
	tampered.Version = "9.9.10"
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tampered)
	}))
	defer bad.Close()
	if _, err := fetchUpdateManifest(context.Background(), bad.URL, pub); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}
