//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRestoreResolvConfSymlink proves a systemd-style symlink survives a
// write/restore cycle instead of being paved over with a regular file.
func TestRestoreResolvConfSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "stub-resolv.conf")
	if err := os.WriteFile(target, []byte("nameserver 9.9.9.9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "resolv.conf")
	bak := filepath.Join(dir, "resolv.conf.egress.bak")
	if err := os.Symlink(target, conf); err != nil {
		t.Fatal(err)
	}

	if err := writeResolvConfAt(conf, bak); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(conf); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("live file must be a regular file after the write")
	}
	if data, _ := os.ReadFile(conf); !resolvConfPointsAtListener(data) {
		t.Error("live file must point at the listener")
	}
	if data, _ := os.ReadFile(target); string(data) != "nameserver 9.9.9.9\n" {
		t.Errorf("symlink target was modified: %q", data)
	}

	if err := restoreResolvConf(conf, bak); err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(conf); err != nil || got != target {
		t.Errorf("symlink not restored: %q, %v", got, err)
	}
}

// TestRestoreResolvConfRegular proves the plain-file round trip still works.
func TestRestoreResolvConfRegular(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "resolv.conf")
	bak := filepath.Join(dir, "resolv.conf.egress.bak")
	_ = os.WriteFile(conf, []byte("nameserver 8.8.8.8\n"), 0644)

	if err := writeResolvConfAt(conf, bak); err != nil {
		t.Fatal(err)
	}
	if err := restoreResolvConf(conf, bak); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(conf); string(data) != "nameserver 8.8.8.8\n" {
		t.Errorf("contents not restored: %q", data)
	}
}
