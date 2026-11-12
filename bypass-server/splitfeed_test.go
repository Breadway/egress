package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func splitTestServer(t *testing.T) *server {
	t.Helper()
	return &server{state: t.TempDir(), splits: map[string][]time.Time{}}
}

func postSplit(t *testing.T, s *server, body string) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/blocked-report", strings.NewReader(body))
	r.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	s.apiBlockedReport(w, r)
	return w.Code
}

func getSeed(t *testing.T, s *server, network string) (int, []string, map[string]int) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/seed?network="+url.QueryEscape(network), nil)
	w := httptest.NewRecorder()
	s.apiSeed(w, r)
	var out struct {
		Domains []struct {
			Domain string `json:"domain"`
			Count  int    `json:"count"`
		} `json:"domains"`
	}
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
	}
	var names []string
	counts := map[string]int{}
	for _, d := range out.Domains {
		names = append(names, d.Domain)
		counts[d.Domain] = d.Count
	}
	return w.Code, names, counts
}

func TestSplitReportMergesTwoDevices(t *testing.T) {
	s := splitTestServer(t)
	network := "NCC|10.179.160.1"
	if code := postSplit(t, s, `{"device":"a","network":"`+network+`","domains":[`+
		`{"domain":"discord.com","evidence":"tls-stall"},{"domain":"poki.com","evidence":"ip-rejected"}]}`); code != http.StatusNoContent {
		t.Fatalf("first report: %d", code)
	}
	if code := postSplit(t, s, `{"device":"b","network":"`+network+`","domains":[`+
		`{"domain":"discord.com","evidence":"tls-stall"}]}`); code != http.StatusNoContent {
		t.Fatalf("second report: %d", code)
	}
	code, names, counts := getSeed(t, s, network)
	if code != http.StatusOK {
		t.Fatalf("seed: %d", code)
	}
	if len(names) != 2 || names[0] != "discord.com" || names[1] != "poki.com" {
		t.Fatalf("domains: %v", names)
	}
	if counts["discord.com"] != 2 || counts["poki.com"] != 1 {
		t.Fatalf("counts: %v", counts)
	}
	// Another network must not see the first network's entries.
	if _, other, _ := getSeed(t, s, "home|192.168.1.1"); len(other) != 0 {
		t.Fatalf("feed leaked across networks: %v", other)
	}
}

func TestSplitReportValidation(t *testing.T) {
	s := splitTestServer(t)
	cases := []string{
		`{"device":"","network":"n","domains":[{"domain":"discord.com","evidence":"tls-stall"}]}`,
		`{"device":"a","network":"","domains":[{"domain":"discord.com","evidence":"tls-stall"}]}`,
		`{"device":"a","network":"n","domains":[]}`,
		`{"device":"a","network":"n","domains":[{"domain":"not a domain","evidence":"tls-stall"}]}`,
		`{"device":"a","network":"n","domains":[{"domain":"discord.com","evidence":"because"}]}`,
		`not json`,
	}
	for i, body := range cases {
		if code := postSplit(t, s, body); code == http.StatusNoContent {
			t.Errorf("case %d accepted %q", i, body)
		}
	}
}

func TestSeedRejectsBadNetwork(t *testing.T) {
	s := splitTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/seed?network=", nil)
	w := httptest.NewRecorder()
	s.apiSeed(w, r)
	if w.Code == http.StatusOK {
		t.Fatal("empty network accepted")
	}
}
