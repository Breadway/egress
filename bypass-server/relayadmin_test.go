package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The relay runs as a different user and reads this file through its group
// bit. A file that already exists with 0600 must end up 0640, or every split
// client loses its blocked path while the server looks healthy.
func TestWriteRelayAuthKeepsGroupReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth")
	if err := os.WriteFile(path, []byte("old:secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeRelayAuth(path, map[string]string{"dev": "pass"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("mode %o, want 640", info.Mode().Perm())
	}
}
