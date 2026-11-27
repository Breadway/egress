package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bearerGet(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "Bearer test-token")
	return r
}

func TestAdminJSONRequiresToken(t *testing.T) {
	s := claimTestServer(t)
	rec := httptest.NewRecorder()
	s.adminJSONOverview(rec, httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("overview without token = %d, want 403", rec.Code)
	}
}

func TestAdminJSONListsAndDeviceInvite(t *testing.T) {
	s := claimTestServer(t)

	rec := httptest.NewRecorder()
	s.adminJSONApplications(rec, bearerGet("/admin/api/applications"))
	if rec.Code != http.StatusOK {
		t.Fatalf("applications = %d (%s)", rec.Code, rec.Body.String())
	}
	var apps struct {
		Applications []adminApplicationRow `json:"applications"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &apps); err != nil {
		t.Fatal(err)
	}
	if len(apps.Applications) != 1 || apps.Applications[0].Name != "Claim Test" {
		t.Fatalf("applications = %+v", apps.Applications)
	}

	rec = httptest.NewRecorder()
	s.adminJSONDevice(rec, bearerPost("/admin/api/device", url.Values{
		"action": {"invite"},
		"label":  {"Desk"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("invite = %d (%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Token == "" {
		t.Fatalf("invite response = %+v", created)
	}

	rec = httptest.NewRecorder()
	s.adminJSONDevices(rec, bearerGet("/admin/api/devices"))
	var devices struct {
		Devices []adminDeviceRow `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices.Devices) != 1 || devices.Devices[0].Label != "Desk" || devices.Devices[0].Status != "issued" {
		t.Fatalf("devices = %+v", devices.Devices)
	}
}

func TestAdminJSONRevokeBoundDevice(t *testing.T) {
	s := claimTestServer(t)
	relayAuth := filepath.Join(s.state, "relay-auth")
	t.Setenv("BYPASS_RELAY_AUTH", relayAuth)
	if err := os.WriteFile(relayAuth, []byte("dev-10-88-0-99-12345678:secret\n"), 0640); err != nil {
		t.Fatal(err)
	}
	dev := device{
		ID: "d-1234abcd", Label: "Bound", Status: "bound",
		PubKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		IP:     "10.88.0.99", RelayUser: "dev-10-88-0-99-12345678",
	}
	reg := deviceRegistry{Version: 1, Devices: []device{dev}}
	data, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.state, "devices.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	old := revokePeerForDevice
	var revoked string
	revokePeerForDevice = func(key string) error { revoked = key; return nil }
	defer func() { revokePeerForDevice = old }()

	rec := httptest.NewRecorder()
	s.adminJSONDevice(rec, bearerPost("/admin/api/device", url.Values{
		"action": {"revoke"}, "id": {dev.ID},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d (%s)", rec.Code, rec.Body.String())
	}
	if revoked != dev.PubKey {
		t.Fatalf("revoked peer = %q, want %q", revoked, dev.PubKey)
	}
	after, err := loadDevices(filepath.Join(s.state, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Devices) != 0 {
		t.Fatalf("device still present: %+v", after.Devices)
	}
	users, err := readRelayAuth(relayAuth)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := users[dev.RelayUser]; ok {
		t.Fatal("relay credential was not removed")
	}
}

func TestAdminJSONApprovePreparesInstaller(t *testing.T) {
	s := claimTestServer(t)
	t.Setenv("BYPASS_GENERIC_WINDOWS", filepath.Join(s.state, "binaries", "egress-test.exe"))
	id := "0123456789abcdef"

	rec := httptest.NewRecorder()
	s.adminJSONApplication(rec, bearerPost("/admin/api/application", url.Values{
		"id":     {id},
		"action": {"approve"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve = %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("approve body = %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.adminJSONApplications(rec, bearerGet("/admin/api/applications"))
	var apps struct {
		Applications []adminApplicationRow `json:"applications"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &apps); err != nil {
		t.Fatal(err)
	}
	if len(apps.Applications) != 1 {
		t.Fatalf("applications = %+v", apps.Applications)
	}
	if apps.Applications[0].DeviceID == "" || apps.Applications[0].State != "ready" {
		t.Fatalf("approved app = %+v", apps.Applications[0])
	}
}
