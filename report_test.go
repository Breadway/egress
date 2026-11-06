package main

import (
	"encoding/json"
	"testing"
	"time"
)

func spoolPayload(ts string) []byte {
	data, _ := json.Marshal(map[string]string{"ts": ts})
	return data
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
