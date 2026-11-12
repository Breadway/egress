package platform

import (
	"crypto/sha256"
	"egress/internal/assets"
	"egress/internal/core"
	"egress/internal/wstunnel"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderedConfigCarriesMarker(t *testing.T) {
	cfg := core.RenderWGConfig(core.TunnelConfig{ClientIP: "10.88.0.4", PrivateKey: "x", Endpoint: "e"})
	if !carriesEgressMarker([]byte(cfg)) {
		t.Error("rendered config must carry the egress marker")
	}
	if !strings.HasPrefix(cfg, egressConfigMarker+"\n") {
		t.Error("marker must be the first line, where WireGuard still parses it as a comment")
	}
}

func TestCarriesEgressMarker(t *testing.T) {
	if !carriesEgressMarker([]byte("# managed by egress\n[Interface]\n")) {
		t.Error("exact marker must match")
	}
	if !carriesEgressMarker([]byte("[Interface]\n  # managed by egress  \n")) {
		t.Error("padded marker must match")
	}
	for _, foreign := range []string{"", "[Interface]\n", "# corporate vpn\n"} {
		if carriesEgressMarker([]byte(foreign)) {
			t.Errorf("%q must not match", foreign)
		}
	}
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestBackupForeignConfig proves a foreign config is preserved once, ours is
// never backed up, and the first backup wins over later foreign files.
func TestBackupForeignConfig(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "wg0.conf")
	bak := filepath.Join(dir, "wg0.conf.egress.bak")

	if err := BackupForeignConfig(live, bak); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bak); !os.IsNotExist(err) {
		t.Error("missing live file must not create a backup")
	}

	_ = os.WriteFile(live, []byte("[Interface]\n# corporate\n"), 0600)
	if err := BackupForeignConfig(live, bak); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(bak); string(data) != "[Interface]\n# corporate\n" {
		t.Errorf("backup holds %q, want the foreign original", data)
	}

	_ = os.WriteFile(live, []byte("[Interface]\n# other foreign\n"), 0600)
	if err := BackupForeignConfig(live, bak); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(bak); string(data) != "[Interface]\n# corporate\n" {
		t.Errorf("first backup must win, holds %q", data)
	}

	ours := core.RenderWGConfig(core.TunnelConfig{ClientIP: "10.88.0.4", PrivateKey: "x", Endpoint: "e"})
	_ = os.WriteFile(live, []byte(ours), 0600)
	_ = os.Remove(bak)
	if err := BackupForeignConfig(live, bak); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bak); !os.IsNotExist(err) {
		t.Error("our own config must never be backed up")
	}
}

// TestRestoreBackedConfig proves remove restores the foreign original only
// when the live file is ours.
func TestRestoreBackedConfig(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "wg0.conf")
	bak := filepath.Join(dir, "wg0.conf.egress.bak")

	if restored, _ := RestoreBackedConfig(live, bak); restored {
		t.Error("missing backup must not restore")
	}

	ours := core.RenderWGConfig(core.TunnelConfig{ClientIP: "10.88.0.4", PrivateKey: "x", Endpoint: "e"})
	_ = os.WriteFile(live, []byte(ours), 0600)
	_ = os.WriteFile(bak, []byte("[Interface]\n# corporate\n"), 0600)
	restored, err := RestoreBackedConfig(live, bak)
	if err != nil || !restored {
		t.Fatalf("ours + backup must restore: %v", err)
	}
	if data, _ := os.ReadFile(live); string(data) != "[Interface]\n# corporate\n" {
		t.Errorf("live holds %q, want the foreign original", data)
	}
	if _, err := os.Stat(bak); !os.IsNotExist(err) {
		t.Error("consumed backup must be removed")
	}

	_ = os.WriteFile(live, []byte("[Interface]\n# user-edited\n"), 0600)
	_ = os.WriteFile(bak, []byte("[Interface]\n# stale\n"), 0600)
	if restored, _ := RestoreBackedConfig(live, bak); restored {
		t.Error("a foreign live file must be left alone, not overwritten with a stale backup")
	}
	if data, _ := os.ReadFile(live); string(data) != "[Interface]\n# user-edited\n" {
		t.Error("foreign live file was modified")
	}
}

// TestWstunnelIsOurs proves a foreign copy is never mistaken for ours.
func TestWstunnelIsOurs(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "wstunnel")
	if wstunnel.WstunnelIsOurs(missing, "00") {
		t.Error("missing file is not ours")
	}
	foreign := writeTemp(t, "wstunnel", "definitely not a real binary")
	if wstunnel.WstunnelIsOurs(foreign, "00") {
		t.Error("foreign binary must not count as ours")
	}
	if len(assets.Wstunnel) == 0 {
		t.Skip("no embedded asset in this build; true path covered by extractEmbedded")
	}
	sum := sha256.Sum256(assets.Wstunnel)
	ours := writeTemp(t, "ours", string(assets.Wstunnel))
	if !wstunnel.WstunnelIsOurs(ours, hex.EncodeToString(sum[:])) {
		t.Error("embedded bytes must count as ours")
	}
}
