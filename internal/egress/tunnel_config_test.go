package egress

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileChanged proves the reinstall-bounce decision: a missing or
// differing config restarts the tunnel, an identical one keeps it live.
func TestWriteFileChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg0.conf")

	changed, err := writeFileChanged(path, []byte("a"))
	if err != nil || !changed {
		t.Fatalf("missing file: changed=%v err=%v, want true/nil", changed, err)
	}

	changed, err = writeFileChanged(path, []byte("a"))
	if err != nil || changed {
		t.Fatalf("identical file: changed=%v err=%v, want false/nil", changed, err)
	}

	changed, err = writeFileChanged(path, []byte("b"))
	if err != nil || !changed {
		t.Fatalf("differing file: changed=%v err=%v, want true/nil", changed, err)
	}

	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v err = %v, want 0600", info.Mode(), err)
	}
}
