package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func spoolPayload(ts string) []byte {
	data, _ := json.Marshal(map[string]string{"ts": ts})
	return data
}

// TestSpoolPathContract pins the cross-process promise: install, the
// supervisor and flush must all resolve the same file, inside a directory
// both sides can use. On Windows that rules out TempDir, which is per-user
// while install runs elevated and the supervisor runs as SYSTEM.
func TestSpoolPathContract(t *testing.T) {
	path := pendingReportPath()
	if filepath.Base(path) != "egress-pending-report.json" {
		t.Errorf("spool file = %q", path)
	}
	if filepath.Dir(path) != spoolDir() {
		t.Errorf("spool dir = %q, want spoolDir %q", filepath.Dir(path), spoolDir())
	}
	if info, err := os.Stat(spoolDir()); err == nil && !info.IsDir() {
		t.Errorf("spoolDir %q is not a directory", spoolDir())
	}
}

func TestSpooledReportStale(t *testing.T) {
	now := time.Now().UTC()
	fresh := spoolPayload(now.Format(time.RFC3339))
	if spooledReportStale(fresh, now, now) {
		t.Error("fresh report must not be stale")
	}
	old := spoolPayload(now.Add(-8 * 24 * time.Hour).Format(time.RFC3339))
	if !spooledReportStale(old, now.Add(-8*24*time.Hour), now) {
		t.Error("8-day-old report must be stale")
	}
	// TS wins over a fresh mtime: an old payload with a new mtime is still stale.
	if !spooledReportStale(old, now, now) {
		t.Error("old TS with fresh mtime must still be stale")
	}
	// Garbage TS falls back to mtime.
	garbage := spoolPayload("not-a-time")
	if spooledReportStale(garbage, now, now) {
		t.Error("garbage TS with fresh mtime must not be stale")
	}
	if !spooledReportStale(garbage, now.Add(-8*24*time.Hour), now) {
		t.Error("garbage TS with old mtime must be stale")
	}
	if !spooledReportStale(nil, now, now) {
		t.Error("empty payload must be stale")
	}
}
