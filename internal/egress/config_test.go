package egress

import (
	"egress/internal/health"
	"encoding/base64"
	"strings"
	"testing"
)

func TestPublicKeyVector(t *testing.T) {
	const private = "MCqypbvCdUOQ3YIitFcch4jsAbxw75Kpr2YWm18KXW4="
	const public = "FIE3IB/8DltS0rF7sywrFM9mCm+svM3sw0SwYWqVWB8="

	got, err := publicKey(private)
	if err != nil {
		t.Fatalf("publicKey: %v", err)
	}
	if got != public {
		t.Fatalf("publicKey = %s, want %s", got, public)
	}
}

func TestNormalizeKey(t *testing.T) {
	const valid = "MCqypbvCdUOQ3YIitFcch4jsAbxw75Kpr2YWm18KXW4="

	if got, err := normalizeKey("  " + valid + "\n"); err != nil || got != valid {
		t.Fatalf("valid key: got %q, %v", got, err)
	}

	cases := map[string]string{
		"empty":      "",
		"short":      "abcd",
		"bad base64": strings.Repeat("!", 44),
		"31 bytes":   base64.StdEncoding.EncodeToString(make([]byte, 31)),
		"33 bytes":   base64.StdEncoding.EncodeToString(make([]byte, 33)),
	}
	for name, key := range cases {
		if _, err := normalizeKey(key); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestGrade(t *testing.T) {
	cases := []struct {
		name string
		r    checkResults
		want string
	}{
		{"all ok", checkResults{Tunnel: "up", Probe: "ok", Exit: aegisIPv4}, "functional"},
		{"dns only", checkResults{Tunnel: "skipped", Probe: "skipped"}, "functional"},
		{"tunnel down", checkResults{Tunnel: "down", Probe: "failed", Exit: "no result"}, "partial"},
		{"wrong exit", checkResults{Tunnel: "up", Probe: "ok", Exit: "got 1.2.3.4, expected " + aegisIPv4}, "partial"},
		{"dns down", checkResults{DNS: "i/o timeout", Tunnel: "down", Probe: "failed", Exit: "no result"}, "failed"},
		{"foreign resolver on port", checkResults{Probe: "ok", Exit: aegisIPv4, Supervisor: "egress service is not active"}, "failed"},
		{"checker unreachable", checkResults{Tunnel: "up", Probe: "ok", Exit: health.ExitUnverifiedPrefix + "timeout"}, "partial"},
	}
	for _, c := range cases {
		if got := c.r.Grade(); got != c.want {
			t.Errorf("%s: grade = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRenderedConfig(t *testing.T) {
	cfg := renderWGConfig(tunnelConfig{
		ClientIP:   "10.88.0.4",
		PrivateKey: "MCqypbvCdUOQ3YIitFcch4jsAbxw75Kpr2YWm18KXW4=",
		Endpoint:   "152.69.174.7:7105",
	})

	for _, want := range []string{
		"Address = 10.88.0.4/32",
		"PrivateKey = MCqypbvCdUOQ3YIitFcch4jsAbxw75Kpr2YWm18KXW4=",
		"PublicKey = " + aegisPublicKey,
		"Endpoint = 152.69.174.7:7105",
		"dev %i",
		"Table = off",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config is missing %q:\n%s", want, cfg)
		}
	}
}

func TestResolveSocksAuthPrefersFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/socks-auth"

	if err := writeSocksAuth(path, "device-user", "device-pass"); err != nil {
		t.Fatal(err)
	}
	// A generic build embeds only bootstrap credentials; the file must win so
	// an update cannot replace a device's own pair.
	oldUser, oldPass := embeddedSocksUser, embeddedSocksPass
	embeddedSocksUser, embeddedSocksPass = "bootstrap", "bootstrap"
	defer func() { embeddedSocksUser, embeddedSocksPass = oldUser, oldPass }()

	user, pass := resolveSocksAuth(path, "", "")
	if user != "device-user" || pass != "device-pass" {
		t.Fatalf("resolved %q/%q, want the file's pair", user, pass)
	}

	// Explicit flags still win, for `proxy --install`.
	user, pass = resolveSocksAuth(path, "flag", "pair")
	if user != "flag" || pass != "pair" {
		t.Fatalf("flags lost: %q/%q", user, pass)
	}

	// No file: fall back to the embedded bootstrap pair.
	user, pass = resolveSocksAuth(dir+"/missing", "", "")
	if user != "bootstrap" || pass != "bootstrap" {
		t.Fatalf("fallback %q/%q", user, pass)
	}
}
