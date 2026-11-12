package egress

import (
	"os"
	"runtime"
	"testing"
)

// TestEnsureInstalledBinary copies the running test binary to the canonical
// install path. It only runs as root, refuses to overwrite a real install,
// and removes what it created.
func TestEnsureInstalledBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires an Administrator shell; run manually")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dest := installedBinaryPath()
	if _, err := os.Stat(dest); err == nil {
		t.Skipf("%s already exists; refusing to overwrite a real install", dest)
	}

	got, err := ensureInstalledBinary()
	if err != nil {
		t.Fatalf("ensureInstalledBinary: %v", err)
	}
	if got != dest {
		t.Fatalf("ensureInstalledBinary = %q, want %q", got, dest)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("installed binary not on disk: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Errorf("installed binary is not executable: %s", info.Mode())
	}
	if info.Size() == 0 {
		t.Error("installed binary is empty")
	}

	// A second call must succeed and return the same path.
	again, err := ensureInstalledBinary()
	if err != nil {
		t.Fatalf("second ensureInstalledBinary: %v", err)
	}
	if again != dest {
		t.Errorf("second call = %q, want %q", again, dest)
	}

	if err := os.Remove(dest); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
