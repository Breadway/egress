package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceFileOverwrites(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "egress.exe")
	src := filepath.Join(dir, "egress.exe.new")
	if err := os.WriteFile(dst, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("new"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(src, dst); err != nil {
		t.Fatalf("replace: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "new" {
		t.Fatalf("content %q err %v, want new", got, err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("source survived the replace")
	}
	if _, err := os.Stat(dst + ".old"); !os.IsNotExist(err) {
		t.Error("aside file survived a replace that did not need one")
	}
}

// TestReplaceFileMovesDestinationAside exercises the fallback path: when the
// destination cannot be renamed over directly, it is moved aside first. A
// directory is used because a running image cannot be simulated portably.
func TestReplaceFileMovesDestinationAside(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "egress.exe")
	if err := os.Mkdir(dst, 0755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "egress.exe.new")
	if err := os.WriteFile(src, []byte("new"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(src, dst); err != nil {
		t.Fatalf("replace over an unreplaceable destination: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "new" {
		t.Fatalf("content %q err %v, want new", got, err)
	}
	aside, _ := filepath.Glob(dst + ".old*")
	if len(aside) != 0 {
		t.Errorf("aside files left behind: %v", aside)
	}
}

func TestReplaceFileCreatesMissingDestination(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "egress.exe")
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("new"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(src, dst); err != nil {
		t.Fatalf("replace onto a missing destination: %v", err)
	}
	if got, err := os.ReadFile(dst); err != nil || string(got) != "new" {
		t.Fatalf("content %q err %v", got, err)
	}
}
