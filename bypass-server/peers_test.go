package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func peersTestServer(t *testing.T, devices ...device) *server {
	t.Helper()
	state := t.TempDir()
	reg := deviceRegistry{Version: 1, Devices: devices}
	data, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "devices.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return &server{state: state}
}

func getPeers(t *testing.T, s *server, key string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/peers?k="+key, nil)
	w := httptest.NewRecorder()
	s.apiPeers(w, r)
	return w
}

func TestPeersRequireAuthentication(t *testing.T) {
	s := peersTestServer(t, device{ID: "d-1", PubKey: "alice-key", IP: "10.88.0.20", Status: "bound"})
	if w := getPeers(t, s, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d, want 401", w.Code)
	}
	if w := getPeers(t, s, "stranger-key"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown key = %d, want 401", w.Code)
	}
	if w := getPeers(t, s, "alice-key"); w.Code != http.StatusOK {
		t.Fatalf("bound key = %d, want 200", w.Code)
	}
}

func TestPeersAreLimitedToTheCallerCircle(t *testing.T) {
	s := peersTestServer(t,
		device{ID: "d-1", PubKey: "alice-key", IP: "10.88.0.20", Status: "bound"},
		device{ID: "d-2", PubKey: "bob-key", IP: "10.88.0.21", Status: "bound"},
		device{ID: "d-3", PubKey: "carol-key", IP: "10.88.0.22", Status: "bound", Circle: "friends"},
	)
	var payload struct {
		Peers []struct {
			PubKey string `json:"pubkey"`
			Circle string `json:"circle"`
		} `json:"peers"`
		Circle string `json:"circle"`
	}

	w := getPeers(t, s, "alice-key")
	if w.Code != http.StatusOK {
		t.Fatalf("alice = %d, want 200", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Circle != "bread" {
		t.Fatalf("circle = %q, want bread", payload.Circle)
	}
	if len(payload.Peers) != 2 {
		t.Fatalf("alice sees %d peers, want 2 (bread only)", len(payload.Peers))
	}
	for _, p := range payload.Peers {
		if p.PubKey == "carol-key" {
			t.Fatal("alice must not see a device outside her circle")
		}
	}

	w = getPeers(t, s, "carol-key")
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Circle != "friends" || len(payload.Peers) != 1 || payload.Peers[0].PubKey != "carol-key" {
		t.Fatalf("carol should only see her own circle: %+v", payload)
	}
}

func TestPeersSkipUnboundDevices(t *testing.T) {
	s := peersTestServer(t,
		device{ID: "d-1", PubKey: "alice-key", IP: "10.88.0.20", Status: "bound"},
		device{ID: "d-2", PubKey: "invite-key", Status: "issued"},
	)
	var payload struct {
		Peers []struct {
			PubKey string `json:"pubkey"`
		} `json:"peers"`
	}
	w := getPeers(t, s, "alice-key")
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Peers) != 1 {
		t.Fatalf("peers = %+v, want only the bound device", payload.Peers)
	}
}

func TestNormalizeCircle(t *testing.T) {
	cases := map[string]string{
		"":          "bread",
		"bread":     "bread",
		" Friends ": "friends",
		"a-b_9":     "bread",
		"x":         "x",
	}
	for in, want := range cases {
		if got := normalizeCircle(in); got != want {
			t.Errorf("normalizeCircle(%q) = %q, want %q", in, got, want)
		}
	}
}
