package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testDerpKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func announceDerp(t *testing.T, s *server, key, derp string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"pubkey": derp})
	r := httptest.NewRequest(http.MethodPost, "/api/derp-key?k="+key, strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	s.apiDerpKey(w, r)
	return w
}

func TestDerpKeyIsAnnouncedAndPublished(t *testing.T) {
	s := peersTestServer(t,
		device{ID: "alice", PubKey: "alice-key", IP: "10.88.0.20", Status: "bound"},
		device{ID: "carol", PubKey: "carol-key", IP: "10.88.0.22", Status: "bound"},
	)
	if w := announceDerp(t, s, "stranger", testDerpKey); w.Code != http.StatusUnauthorized {
		t.Fatalf("stranger = %d, want 401", w.Code)
	}
	if w := announceDerp(t, s, "alice-key", "not-a-key"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad key = %d, want 400", w.Code)
	}
	if w := announceDerp(t, s, "alice-key", testDerpKey); w.Code != http.StatusOK {
		t.Fatalf("announce = %d, want 200", w.Code)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/peers?k=carol-key", nil)
	w := httptest.NewRecorder()
	s.apiPeers(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("peers = %d", w.Code)
	}
	var payload struct {
		Peers []struct {
			ID         string `json:"-"`
			Label      string `json:"label"`
			DerpPubKey string `json:"derp_pubkey"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range payload.Peers {
		if p.DerpPubKey == testDerpKey {
			found = true
		}
	}
	if !found {
		t.Fatalf("peer list did not carry the relay key: %+v", payload.Peers)
	}
}
