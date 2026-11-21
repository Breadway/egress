package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	exitBaseKey   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	exitClientKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	exitBobKey    = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	slotKeyA      = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
)

func announceSlot(t *testing.T, s *server, exitKey, client, relayKey string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"client": client, "relay_key": relayKey})
	r := httptest.NewRequest(http.MethodPost, "/api/exit/slot?k="+exitKey, strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	s.apiExitSlot(w, r)
	return w
}

func peerExitKey(t *testing.T, s *server, callerKey string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/peer-exits?k="+callerKey, nil)
	w := httptest.NewRecorder()
	s.apiPeerExits(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("peer exits = %d", w.Code)
	}
	var out struct {
		Exits []struct {
			RelayKey string `json:"relay_key"`
		} `json:"exits"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Exits) != 1 {
		t.Fatalf("exits = %+v", out.Exits)
	}
	return out.Exits[0].RelayKey
}

func TestExitSlotIsPerClient(t *testing.T) {
	s := peersTestServer(t,
		device{ID: "alice", Label: "exit", PubKey: "alice-key", IP: "10.88.0.20", Status: "bound", DerpPubKey: exitBaseKey},
		device{ID: "carol", Label: "client", PubKey: "carol-key", IP: "10.88.0.22", Status: "bound", DerpPubKey: exitClientKey},
		device{ID: "bob", Label: "other", PubKey: "bob-key", IP: "10.88.0.21", Status: "bound", DerpPubKey: exitBobKey},
	)
	if w := announceDerpExit(t, s, "alice-key"); w.Code != http.StatusOK {
		t.Fatalf("exit announce = %d", w.Code)
	}
	if w := useExit(t, s, "carol-key", "alice", http.MethodPost); w.Code != http.StatusOK {
		t.Fatalf("use = %d", w.Code)
	}
	// Before a slot exists the client sees the exit's base relay key.
	if got := peerExitKey(t, s, "carol-key"); got != exitBaseKey {
		t.Fatalf("base relay key = %q", got)
	}
	if w := announceSlot(t, s, "alice-key", "carol", slotKeyA); w.Code != http.StatusOK {
		t.Fatalf("slot announce = %d", w.Code)
	}
	// The slot is visible only to that client.
	if got := peerExitKey(t, s, "carol-key"); got != slotKeyA {
		t.Fatalf("carol slot = %q", got)
	}
	// Another circle member sees the exit's base key, not carol's slot.
	if got := peerExitKey(t, s, "bob-key"); got != exitBaseKey {
		t.Fatalf("bob saw carol's slot: %q", got)
	}
	// Only the exit can announce a slot, and only for a client using it.
	if w := announceSlot(t, s, "bob-key", "carol", slotKeyA); w.Code != http.StatusBadRequest {
		t.Fatalf("non-exit slot = %d, want 400", w.Code)
	}
	if w := announceSlot(t, s, "alice-key", "bob", slotKeyA); w.Code != http.StatusBadRequest {
		t.Fatalf("slot for non-user = %d, want 400", w.Code)
	}
	// The exit sees the slot it announced for the client.
	r := httptest.NewRequest(http.MethodGet, "/api/exit/clients?k=alice-key", nil)
	w := httptest.NewRecorder()
	s.apiExitClients(w, r)
	var clients struct {
		Clients []struct {
			ID           string `json:"id"`
			SlotRelayKey string `json:"slot_relay_key"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &clients); err != nil {
		t.Fatal(err)
	}
	if len(clients.Clients) != 1 || clients.Clients[0].ID != "carol" || clients.Clients[0].SlotRelayKey != slotKeyA {
		t.Fatalf("clients = %+v", clients.Clients)
	}

	// Leaving the exit removes the slot.
	if w := useExit(t, s, "carol-key", "", http.MethodDelete); w.Code != http.StatusNoContent {
		t.Fatalf("withdraw = %d", w.Code)
	}
	if got := peerExitKey(t, s, "carol-key"); got != exitBaseKey {
		t.Fatalf("slot survived the opt-out: %q", got)
	}
	reg, _ := loadExitSlots(s.exitSlotsPath())
	if len(reg.Slots) != 0 {
		t.Fatalf("slots = %+v", reg.Slots)
	}
}
