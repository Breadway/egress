//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeCommand(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestTailscaleDNSIsTakenAndRestored(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	logPath := filepath.Join(dir, "calls")
	t.Setenv("EGRESS_STATE_DIR", state)
	t.Setenv("PATH", dir)
	fakeCommand(t, dir, "tailscale", `
case "$1 $2" in
  "dns status") echo "Tailscale DNS: enabled." ;;
  "set --accept-dns=false") echo "set false" >> "`+logPath+`" ;;
  "set --accept-dns=true") echo "set true" >> "`+logPath+`" ;;
esac
`)
	fakeCommand(t, dir, "resolvectl", `exit 0`)

	if !tailscaleDNSEnabled() {
		t.Fatal("fake tailscale should report DNS enabled")
	}
	disableTailscaleDNS()
	marker := filepath.Join(state, tailscaleDNSMarker)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker not written: %v", err)
	}
	restoreTailscaleDNS()
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker not removed: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "set false") || !strings.Contains(text, "set true") {
		t.Fatalf("tailscale calls = %q, want both directions", text)
	}
}
