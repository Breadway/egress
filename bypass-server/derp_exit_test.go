package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func announceDerpExit(t *testing.T, s *server, key string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/exit/announce?k="+key, strings.NewReader(`{"transport":"derp"}`))
	w := httptest.NewRecorder()
	s.apiExitAnnounce(w, r)
	return w
}

func TestDerpExitAnnounceAndPublish(t *testing.T) {
	const exitKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const clientKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	s := peersTestServer(t,
		device{ID: "alice", Label: "exit", PubKey: "alice-key", IP: "10.88.0.20", Status: "bound", DerpPubKey: exitKey},
		device{ID: "carol", Label: "client", PubKey: "carol-key", IP: "10.88.0.22", Status: "bound", DerpPubKey: clientKey},
		device{ID: "bob", Label: "no-relay", PubKey: "bob-key", IP: "10.88.0.21", Status: "bound"},
	)
	if w := announceDerpExit(t, s, "bob-key"); w.Code != http.StatusBadRequest {
		t.Fatalf("derp announce without a relay key = %d, want 400", w.Code)
	}
	if w := announceDerpExit(t, s, "alice-key"); w.Code != http.StatusOK {
		t.Fatalf("announce = %d", w.Code)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/peer-exits?k=carol-key", nil)
	w := httptest.NewRecorder()
	s.apiPeerExits(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("peer exits = %d", w.Code)
	}
	var exits struct {
		Exits []struct {
			ID        string `json:"id"`
			Transport string `json:"transport"`
			Endpoint  string `json:"endpoint"`
			PubKey    string `json:"pubkey"`
			RelayKey  string `json:"relay_key"`
		} `json:"exits"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &exits); err != nil {
		t.Fatal(err)
	}
	if len(exits.Exits) != 1 {
		t.Fatalf("exits = %+v", exits.Exits)
	}
	e := exits.Exits[0]
	if e.Transport != "derp" || e.RelayKey != exitKey || e.Endpoint != "" || e.PubKey != "alice-key" {
		t.Fatalf("derp exit = %+v", e)
	}

	// The client opts in, and the exit sees the client's relay key, which is
	// what it needs to open the relayed UDP link.
	if w := useExit(t, s, "carol-key", "alice", http.MethodPost); w.Code != http.StatusOK {
		t.Fatalf("use = %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "/api/exit/clients?k=alice-key", nil)
	w = httptest.NewRecorder()
	s.apiExitClients(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("clients = %d", w.Code)
	}
	var clients struct {
		Clients []struct {
			ID         string `json:"id"`
			DerpPubKey string `json:"derp_pubkey"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &clients); err != nil {
		t.Fatal(err)
	}
	if len(clients.Clients) != 1 || clients.Clients[0].ID != "carol" || clients.Clients[0].DerpPubKey != clientKey {
		t.Fatalf("clients = %+v", clients.Clients)
	}
}
