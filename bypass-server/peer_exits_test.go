package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func announceExit(t *testing.T, s *server, key, endpoint string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"endpoint":` + strconvQuote(endpoint) + `,"path":"/peer-exit"}`
	r := httptest.NewRequest(http.MethodPost, "/api/exit/announce?k="+key, strings.NewReader(body))
	w := httptest.NewRecorder()
	s.apiExitAnnounce(w, r)
	return w
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func getPeerExits(t *testing.T, s *server, key string) (int, []string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/peer-exits?k="+key, nil)
	w := httptest.NewRecorder()
	s.apiPeerExits(w, r)
	var payload struct {
		Exits []struct {
			ID       string `json:"id"`
			Endpoint string `json:"endpoint"`
			PubKey   string `json:"pubkey"`
		} `json:"exits"`
	}
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
	}
	ids := make([]string, 0, len(payload.Exits))
	for _, e := range payload.Exits {
		ids = append(ids, e.ID)
	}
	return w.Code, ids
}

func TestExitAnnounceRequiresABoundDevice(t *testing.T) {
	s := peersTestServer(t, device{ID: "d-1", PubKey: "alice-key", IP: "10.88.0.20", Status: "bound"})
	if w := announceExit(t, s, "stranger", "203.0.113.9:7443"); w.Code != http.StatusUnauthorized {
		t.Fatalf("stranger = %d, want 401", w.Code)
	}
	if w := announceExit(t, s, "alice-key", "not-an-endpoint"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad endpoint = %d, want 400", w.Code)
	}
	if w := announceExit(t, s, "alice-key", "203.0.113.9:7443"); w.Code != http.StatusOK {
		t.Fatalf("announce = %d, want 200", w.Code)
	}
	reg, err := loadPeerExits(s.peerExitsPath())
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Exits) != 1 || reg.Exits[0].PubKey != "alice-key" || reg.Exits[0].Path != "/peer-exit" {
		t.Fatalf("registry = %+v", reg.Exits)
	}
}

func TestPeerExitsAreScopedToTheCircle(t *testing.T) {
	s := peersTestServer(t,
		device{ID: "d-1", PubKey: "alice-key", IP: "10.88.0.20", Status: "bound"},
		device{ID: "d-2", PubKey: "carol-key", IP: "10.88.0.22", Status: "bound"},
		device{ID: "d-3", PubKey: "bob-key", IP: "10.88.0.21", Status: "bound", Circle: "friends"},
	)
	for _, kv := range []struct{ key, endpoint string }{
		{"alice-key", "203.0.113.9:7443"},
		{"carol-key", "203.0.113.10:7443"},
		{"bob-key", "203.0.113.11:7443"},
	} {
		if w := announceExit(t, s, kv.key, kv.endpoint); w.Code != http.StatusOK {
			t.Fatalf("announce %s = %d", kv.key, w.Code)
		}
	}
	code, ids := getPeerExits(t, s, "alice-key")
	if code != http.StatusOK {
		t.Fatalf("alice = %d", code)
	}
	// Alice is in bread with carol; bob is in friends and must not appear.
	if len(ids) != 1 || ids[0] != "d-2" {
		t.Fatalf("alice sees %v, want only d-2", ids)
	}
	code, ids = getPeerExits(t, s, "bob-key")
	if code != http.StatusOK || len(ids) != 0 {
		t.Fatalf("bob sees %v, want nobody in his circle", ids)
	}
	if code, _ := getPeerExits(t, s, "stranger"); code != http.StatusUnauthorized {
		t.Fatalf("stranger = %d, want 401", code)
	}
}

func TestExitAnnounceCanBeWithdrawn(t *testing.T) {
	s := peersTestServer(t, device{ID: "d-1", PubKey: "alice-key", IP: "10.88.0.20", Status: "bound"})
	if w := announceExit(t, s, "alice-key", "203.0.113.9:7443"); w.Code != http.StatusOK {
		t.Fatalf("announce = %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodDelete, "/api/exit/announce?k=alice-key", nil)
	w := httptest.NewRecorder()
	s.apiExitAnnounce(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("withdraw = %d, want 204", w.Code)
	}
	reg, _ := loadPeerExits(s.peerExitsPath())
	if len(reg.Exits) != 0 {
		t.Fatalf("registry = %+v, want empty", reg.Exits)
	}
}
