package egress

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExitSlotKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exit-clients", "d-test.key")
	priv1, pub1, err := loadOrCreateExitSlotKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	priv2, pub2, err := loadOrCreateExitSlotKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if priv1 != priv2 || pub1 != pub2 {
		t.Fatalf("slot key changed across loads: %x/%x vs %x/%x", priv1[:4], priv2[:4], []byte(pub1)[:4], []byte(pub2)[:4])
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key mode = %o, want 600", info.Mode().Perm())
	}
}
