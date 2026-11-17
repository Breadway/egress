package supervisor

import (
	"bytes"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNoteRestorePausesAfterRepeatedRemovals pins the back-off: a scanner that
// quarantines the tunneler must not produce an endless restore loop with no
// explanation.
func TestNoteRestorePausesAfterRepeatedRemovals(t *testing.T) {
	var buf bytes.Buffer
	s := &Supervisor{log: log.New(&buf, "", 0)}
	path := filepath.Join("install", "wstunnel.exe")

	for i := 0; i < tunnelerRestoreLimit; i++ {
		s.noteRestore(path)
	}

	out := buf.String()
	if !strings.Contains(out, "removed 3 times in a row") {
		t.Errorf("log does not explain the loop:\n%s", out)
	}
	if !strings.Contains(out, filepath.Dir(path)) {
		t.Errorf("log does not name the directory to exclude:\n%s", out)
	}
	if s.restorePaused.IsZero() || time.Until(s.restorePaused) <= 0 {
		t.Errorf("restorePaused = %v, want a future pause", s.restorePaused)
	}
	if s.restores != 0 {
		t.Errorf("restores = %d, want the counter reset after pausing", s.restores)
	}
}

// TestNoteRestoreQuietBelowLimit keeps the normal case useful: one restore is
// logged as a restore, and nothing is paused yet.
func TestNoteRestoreQuietBelowLimit(t *testing.T) {
	var buf bytes.Buffer
	s := &Supervisor{log: log.New(&buf, "", 0)}
	path := filepath.Join("install", "wstunnel.exe")

	s.noteRestore(path)

	out := buf.String()
	if !strings.Contains(out, "restored the tunneler") {
		t.Errorf("missing restore log:\n%s", out)
	}
	if strings.Contains(out, "removed") {
		t.Errorf("warned about quarantine after a single restore:\n%s", out)
	}
	if !s.restorePaused.IsZero() {
		t.Errorf("restorePaused = %v, want zero", s.restorePaused)
	}
	if s.restores != 1 {
		t.Errorf("restores = %d, want 1", s.restores)
	}
}
