package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func useExit(t *testing.T, s *server, key, exit string, method string) *httptest.ResponseRecorder {
	t.Helper()
	body := ""
	if method == http.MethodPost {
		b, _ := json.Marshal(map[string]string{"exit": exit})
		body = string(b)
	}
	r := httptest.NewRequest(method, "/api/exit/use?k="+key, strings.NewReader(body))
	w := httptest.NewRecorder()
	s.apiExitUse(w, r)
	return w
}

func exitClients(t *testing.T, s *server, key string) []string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/exit/clients?k="+key, nil)
	w := httptest.NewRecorder()
	s.apiExitClients(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("clients = %d", w.Code)
	}
	var payload struct {
		Clients []struct {
			ID string `json:"id"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(payload.Clients))
	for _, c := range payload.Clients {
		ids = append(ids, c.ID)
	}
	return ids
}

func TestExitUseIsScopedToTheCircle(t *testing.T) {
	s := peersTestServer(t,
		device{ID: "alice", PubKey: "alice-key", IP: "10.88.0.20", Status: "bound"},
		device{ID: "carol", PubKey: "carol-key", IP: "10.88.0.22", Status: "bound"},
		device{ID: "bob", PubKey: "bob-key", IP: "10.88.0.21", Status: "bound", Circle: "friends"},
	)
	if w := announceExit(t, s, "carol-key", "203.0.113.9:7443"); w.Code != http.StatusOK {
		t.Fatalf("announce = %d", w.Code)
	}

	if w := useExit(t, s, "alice-key", "carol", http.MethodPost); w.Code != http.StatusOK {
		t.Fatalf("use = %d, want 200", w.Code)
	}
	if ids := exitClients(t, s, "carol-key"); len(ids) != 1 || ids[0] != "alice" {
		t.Fatalf("carol clients = %v, want [alice]", ids)
	}
	if w := useExit(t, s, "bob-key", "carol", http.MethodPost); w.Code != http.StatusBadRequest {
		t.Fatalf("cross-circle use = %d, want 400", w.Code)
	}
	if w := useExit(t, s, "carol-key", "carol", http.MethodPost); w.Code != http.StatusBadRequest {
		t.Fatalf("self use = %d, want 400", w.Code)
	}

	if w := useExit(t, s, "alice-key", "", http.MethodDelete); w.Code != http.StatusNoContent {
		t.Fatalf("withdraw = %d, want 204", w.Code)
	}
	if ids := exitClients(t, s, "carol-key"); len(ids) != 0 {
		t.Fatalf("carol clients = %v, want none", ids)
	}
}
