package egress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"egress/internal/core"
)

func TestFindEnrollToken(t *testing.T) {
	t.Setenv("EGRESS_ENROLL_TOKEN", "")
	if got := findEnrollToken("flag-token"); got != "flag-token" {
		t.Fatalf("flag token %q", got)
	}
	t.Setenv("EGRESS_ENROLL_TOKEN", "env-token")
	if got := findEnrollToken(""); got != "env-token" {
		t.Fatalf("env token %q", got)
	}
}

func TestReadTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enroll.txt")
	if err := os.WriteFile(path, []byte("# invite\n\n  dG9rZW4tZXhhbXBsZQ  \nignored\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := readTokenFile(path); got != "dG9rZW4tZXhhbXBsZQ" {
		t.Fatalf("token %q", got)
	}
	if got := readTokenFile(filepath.Join(t.TempDir(), "missing")); got != "" {
		t.Fatalf("missing file returned %q", got)
	}
}

func TestEnrollDevice(t *testing.T) {
	var got struct {
		Token    string `json:"token"`
		PubKey   string `json:"pubkey"`
		Platform string `json:"platform"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/enroll" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(enrollCredentials{
			Device: "d-0123abcd", IP: "10.88.0.42",
			RelayUser: "dev-10-88-0-42-0123abcd", RelayPass: "0123456789abcdefghijklmn",
		})
	}))
	defer srv.Close()

	creds, err := enrollDevice(context.Background(), srv.URL, "token-123", "pubkey-456", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "token-123" || got.PubKey != "pubkey-456" || got.Platform == "" {
		t.Fatalf("payload %+v", got)
	}
	if creds.IP != "10.88.0.42" || !creds.hasRelay() {
		t.Fatalf("credentials %+v", creds)
	}
}

func TestEnrollDeviceRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "token already used", http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, err := enrollDevice(context.Background(), srv.URL, "t", "p", ""); err == nil {
		t.Fatal("a refused enrollment returned success")
	}
}

func TestGeneratePrivateKeyRoundTrip(t *testing.T) {
	key, err := core.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.NormalizeKey(key); err != nil {
		t.Fatalf("generated key invalid: %v", err)
	}
	pub, err := core.PublicKey(key)
	if err != nil || len(pub) != 44 {
		t.Fatalf("public key %q err %v", pub, err)
	}
}
