package main

import "testing"

// TestFleetCountsAgree pins the single source of truth: an application's state
// follows the device it points at, so Applications, Devices and Overview cannot
// disagree about how many installs are waiting, ready or done.
func TestFleetCountsAgree(t *testing.T) {
	s := reportTestServer(t)

	apps := []application{
		{ID: "aaaaaaaaaaaaaaaa", Name: "waiting"},
		{ID: "bbbbbbbbbbbbbbbb", Name: "ready", Reviewed: true, DeviceID: "d-11111111"},
		{ID: "cccccccccccccccc", Name: "installed", Reviewed: true, DeviceID: "d-22222222"},
		{ID: "dddddddddddddddd", Name: "failed", Reviewed: true, ProvisionError: "no installer"},
	}
	for i := range apps {
		if err := s.saveApplication(&apps[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveDevices(s.devicesPath(), deviceRegistry{
		Version: 1,
		Devices: []device{
			{ID: "d-11111111", Status: "issued", TokenHash: "x"},
			{ID: "d-22222222", Status: "bound", TokenHash: "y", PubKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="},
		},
	}); err != nil {
		t.Fatal(err)
	}

	f := s.loadFleet()
	waiting, ready, installed, attention := f.counts()
	if waiting != 1 || ready != 1 || installed != 1 || attention != 1 {
		t.Fatalf("counts = waiting %d ready %d installed %d attention %d, want 1/1/1/1",
			waiting, ready, installed, attention)
	}
	if bound, open := f.boundDevices(); bound != 1 || open != 1 {
		t.Errorf("devices = bound %d open %d, want 1/1", bound, open)
	}

	// The application marked installed must resolve to the bound device, which
	// is what the Report column reads.
	d, ok := f.appDevice(apps[2])
	if !ok || d.Status != "bound" {
		t.Errorf("installed application does not map to its bound device: %+v ok=%v", d, ok)
	}
	if a, ok := f.deviceApp(d); !ok || a.ID != apps[2].ID {
		t.Errorf("device does not map back to its application: %+v ok=%v", a, ok)
	}
	if chip, _ := f.appState(apps[3]); chip != "failed" {
		t.Errorf("provision error state = %q, want failed", chip)
	}
}
