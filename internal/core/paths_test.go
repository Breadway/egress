package core

import (
	"path/filepath"
	"testing"
)

func TestStateDirOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EGRESS_STATE_DIR", dir)
	if got := DeviceIdentityPath(); got != filepath.Join(dir, "device.json") {
		t.Fatalf("device identity = %q", got)
	}
	if got := CredentialPath(); got != filepath.Join(dir, "socks-auth") {
		t.Fatalf("credential = %q", got)
	}
}
