package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeReport and writeHeartbeat seed the two signals deviceState reads.
func writeReport(t *testing.T, s *server, pubkey, status string, at time.Time) {
	t.Helper()
	dir := filepath.Join(s.state, "reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	body := storedReport{
		Received: at.UTC().Format(time.RFC3339),
		Report:   deviceReport{Pubkey: pubkey, Status: status, Version: "0.4.58"},
	}
	data, _ := json.Marshal(body)
	if err := os.WriteFile(filepath.Join(dir, reportSlug(pubkey)+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeHeartbeat(t *testing.T, s *server, pubkey string, at time.Time) {
	t.Helper()
	if err := os.MkdirAll(s.heartbeatDir(), 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(heartbeat{Last: at.UTC().Format(time.RFC3339), Version: "0.4.58"})
	if err := os.WriteFile(s.heartbeatPath(pubkey), data, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestDeviceStateLaws pins the classification an operator acts on. Getting
// this wrong is what made a working machine read as "off".
func TestDeviceStateLaws(t *testing.T) {
	const key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	now := time.Now()

	cases := []struct {
		name    string
		dev     device
		report  *time.Time
		status  string
		beat    *time.Time
		want    string
		wantCls string
	}{
		{name: "never", dev: device{PubKey: key, Status: "bound"}, want: "never installed", wantCls: "warn"},
		{name: "invite", dev: device{PubKey: key, Status: "issued"}, want: "invite"},
		{name: "healthy", dev: device{PubKey: key, Status: "bound"}, report: &now, status: "functional", beat: &now, want: "healthy", wantCls: "ok"},
		{name: "degraded", dev: device{PubKey: key, Status: "bound"}, report: &now, status: "partial", beat: &now, want: "degraded", wantCls: "warn"},
		{name: "polling", dev: device{PubKey: key, Status: "bound"}, status: "functional", beat: &now, want: "polling", wantCls: "warn"},
		{name: "no heartbeat old build", dev: device{PubKey: key, Status: "bound"}, report: &now, status: "partial", want: "no heartbeat", wantCls: "warn"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := reportTestServer(t)
			if tc.report != nil {
				writeReport(t, s, key, tc.status, *tc.report)
			}
			if tc.beat != nil {
				writeHeartbeat(t, s, key, *tc.beat)
			}
			got, class, _, _, _ := s.deviceState(tc.dev)
			if got != tc.want || class != tc.wantCls {
				t.Errorf("state = %q/%q, want %q/%q", got, class, tc.want, tc.wantCls)
			}
		})
	}
}

// TestDeviceStateOffWhenSilent is the one case that must be loud: nothing at
// all from the machine for a day.
func TestDeviceStateOffWhenSilent(t *testing.T) {
	const key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	s := reportTestServer(t)
	old := time.Now().Add(-30 * time.Hour)
	writeReport(t, s, key, "functional", old)
	writeHeartbeat(t, s, key, old)
	got, class, _, _, _ := s.deviceState(device{PubKey: key, Status: "bound"})
	if got != "off" || class != "bad" {
		t.Errorf("state = %q/%q, want off/bad", got, class)
	}
}
