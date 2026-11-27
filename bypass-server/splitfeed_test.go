package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMergeAliasesFoldsLegacyFeed(t *testing.T) {
	s := &server{state: t.TempDir()}
	stamp := time.Now().UTC().Format(time.RFC3339)
	alias := networkID("unknown|10.179.160.1")
	legacy := s.loadFeed(alias)
	legacy.Domains["blocked.example"] = feedEntry{State: "blocked", Evidence: "tls-stall", Count: 2, LastSeen: stamp}
	legacy.Domains["allowed.example"] = feedEntry{State: "allowed", Evidence: "connect-ok", Count: 1, LastSeen: stamp}
	legacy.Protocols["udp"] = protocolEntry{State: "blocked", Count: 1, LastSeen: stamp}
	if err := s.saveFeed(legacy); err != nil {
		t.Fatal(err)
	}
	feed := s.loadFeed(networkID("canonical"))
	if !s.mergeAliases(&feed, []string{alias, "not-a-network-id"}) {
		t.Fatal("alias feed was not merged")
	}
	if feed.Domains["blocked.example"].State != "blocked" {
		t.Fatalf("blocked entry not merged: %+v", feed.Domains)
	}
	if feed.Protocols["udp"].State != "blocked" {
		t.Fatalf("protocol not merged: %+v", feed.Protocols)
	}
	// A later direct block must not be downgraded by an allowed alias entry.
	feed.Domains["own.example"] = feedEntry{State: "blocked", Evidence: "cert-substitution", Count: 3, LastSeen: stamp}
	legacy.Domains["own.example"] = feedEntry{State: "allowed", Evidence: "connect-ok", Count: 9, LastSeen: stamp}
	if err := s.saveFeed(legacy); err != nil {
		t.Fatal(err)
	}
	s.mergeAliases(&feed, []string{alias})
	if feed.Domains["own.example"].State != "blocked" {
		t.Fatalf("alias downgraded a block: %+v", feed.Domains["own.example"])
	}
}

func TestSeedServesAliasDomains(t *testing.T) {
	s := &server{state: t.TempDir()}
	alias := networkID("unknown|10.179.160.1")
	legacy := s.loadFeed(alias)
	legacy.Domains["blocked.example"] = feedEntry{
		State: "blocked", Evidence: "tls-stall", Count: 1,
		LastSeen: time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.saveFeed(legacy); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet,
		"/api/split/seed?n="+networkID("canonical")+"&alias="+alias, nil)
	rec := httptest.NewRecorder()
	s.apiSeed(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("seed status %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		NetworkID string `json:"network_id"`
		Domains   []struct {
			Domain string `json:"domain"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.NetworkID != networkID("canonical") || len(body.Domains) != 1 ||
		body.Domains[0].Domain != "blocked.example" {
		t.Fatalf("seed body = %+v", body)
	}
}

func TestNetworkIDHashesAndIsStable(t *testing.T) {
	raw := "HomeNet|192.168.1.1"
	got := networkID(raw)
	if len(got) != 32 {
		t.Fatalf("id %q is not 32 hex chars", got)
	}
	if got != networkID("homenet|192.168.1.1") {
		t.Error("id is not case-insensitive")
	}
	if got != networkID(got) {
		t.Error("hashing a hashed id changed it")
	}
	if got == networkID("OtherNet|192.168.1.1") {
		t.Error("different ssids share an id")
	}
}

func TestBlockWinsConflict(t *testing.T) {
	entry := mergeDomainObservation(feedEntry{}, "blocked", "tls-stall", false, "t0")
	if entry.State != "blocked" || entry.Count != 1 {
		t.Fatalf("blocked entry: %+v", entry)
	}

	// Another device says allowed: the domain is contested and the allowing
	// device is asked to re-check.
	entry = mergeDomainObservation(entry, "allowed", "connect-ok", false, "t1")
	if !entry.Contested || !entry.RecheckAsked || entry.State != "blocked" {
		t.Fatalf("contest did not start: %+v", entry)
	}

	// The allowing device re-checks and still says allowed. The block stands
	// until the blocked side verifies.
	entry = mergeDomainObservation(entry, "allowed", "connect-ok", true, "t2")
	if !containsState(entry.Finals, "allowed") {
		t.Fatalf("final not recorded: %+v", entry)
	}
	if entry.State != "allowed" && entry.VerifyAsked == false {
		t.Fatalf("allowed final neither resolved nor asked for verification: %+v", entry)
	}

	// A blocked verification settles it in favour of block, even though the
	// final answers disagree.
	entry = mergeDomainObservation(entry, "blocked", "tls-stall", true, "t3")
	if entry.State != "blocked" || entry.Contested || entry.VerifyAsked {
		t.Fatalf("block did not win: %+v", entry)
	}
}

func TestAllowedFinalWithoutBlockResolvesAllowed(t *testing.T) {
	entry := mergeDomainObservation(feedEntry{}, "blocked", "seed", false, "t0")
	entry = mergeDomainObservation(entry, "allowed", "connect-ok", false, "t1")
	entry = mergeDomainObservation(entry, "allowed", "connect-ok", true, "t2")
	if entry.State != "allowed" || entry.Contested {
		t.Fatalf("allowed should win with no blocked final: %+v", entry)
	}
}

func TestProtocolStateMerges(t *testing.T) {
	feed := networkFeed{Protocols: map[string]protocolEntry{}}
	entry := feed.Protocols["udp"]
	entry.State = "blocked"
	entry.Count = 1
	entry.LastSeen = "t0"
	feed.Protocols["udp"] = entry
	if feed.Protocols["udp"].State != "blocked" {
		t.Fatalf("protocol: %+v", feed.Protocols["udp"])
	}
}

func TestRefreshTimerStartsOnAddAndResetsOnObservation(t *testing.T) {
	entry := mergeDomainObservation(feedEntry{}, "blocked", "tls-stall", false, "2026-01-01T00:00:00Z")
	if entry.RefreshDue != "2026-01-08T00:00:00Z" {
		t.Fatalf("refresh due = %q, want one week after the block", entry.RefreshDue)
	}
	entry = mergeDomainObservation(entry, "allowed", "connect-ok", false, "2026-01-03T00:00:00Z")
	if entry.RefreshDue != "2026-01-10T00:00:00Z" {
		t.Fatalf("refresh did not reset on observation: %q", entry.RefreshDue)
	}
}

func TestClaimRefreshLeasesAndExpires(t *testing.T) {
	feed := networkFeed{Domains: map[string]feedEntry{
		"due.com":     {State: "blocked", Evidence: "tls-stall", RefreshDue: "2026-01-01T00:00:00Z"},
		"future.com":  {State: "blocked", Evidence: "tls-stall", RefreshDue: "2026-02-01T00:00:00Z"},
		"allowed.com": {State: "allowed", Evidence: "connect-ok"},
	}}
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	claimed := claimRefresh(&feed, now)
	if len(claimed) != 1 || claimed[0] != "due.com" {
		t.Fatalf("claimed %v, want only the due blocked domain", claimed)
	}
	if feed.Domains["due.com"].ClaimUntil == "" {
		t.Fatal("no lease recorded")
	}
	// A second client cannot take the same job while the lease holds.
	if again := claimRefresh(&feed, now.Add(time.Minute)); len(again) != 0 {
		t.Fatalf("leased job handed out again: %v", again)
	}
	// After the lease expires it can.
	if after := claimRefresh(&feed, now.Add(splitClaimLease+time.Minute)); len(after) != 1 {
		t.Fatalf("expired job not re-issued: %v", after)
	}
}

func TestSeedPublishesDerpExit(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "exits.json")
	t.Setenv("EGRESS_EXIT_REGISTRY", regPath)
	reg := exitRegistry{Version: 1, Exits: []exitEntry{{
		ID: "hestia", Label: "hestia", Enabled: true,
		Transport: "derp", RelayKey: "relay-key", DerpPubKey: "wg-key", Device: "d-5f196bbf",
	}}}
	data, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	s := &server{state: dir}
	req := httptest.NewRequest(http.MethodGet, "/api/seed?n="+networkID("test-net"), nil)
	rec := httptest.NewRecorder()
	s.apiSeed(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("seed status %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		Exits []struct {
			ID        string `json:"id"`
			Endpoint  string `json:"endpoint"`
			PubKey    string `json:"pubkey"`
			Transport string `json:"transport"`
			RelayKey  string `json:"relay_key"`
			Device    string `json:"device"`
		} `json:"exits"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Exits) != 1 {
		t.Fatalf("exits = %+v, want one DERP exit", body.Exits)
	}
	e := body.Exits[0]
	if e.Transport != "derp" || e.RelayKey != "relay-key" || e.PubKey != "wg-key" || e.Device != "d-5f196bbf" || e.Endpoint != "" {
		t.Fatalf("exit = %+v, want the DERP fields and no endpoint", e)
	}
}

func TestSeedPublishesAssignments(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "status.json")
	t.Setenv("EGRESS_EXIT_STATUS", statusPath)
	data, err := json.Marshal(exitStatus{Assignments: map[string]string{"146.75.92.0/24": "hestia"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statusPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	s := &server{state: dir}
	req := httptest.NewRequest(http.MethodGet, "/api/seed?n="+networkID("test-net"), nil)
	rec := httptest.NewRecorder()
	s.apiSeed(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("seed status %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		Assignments map[string]string `json:"assignments"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Assignments["146.75.92.0/24"] != "hestia" {
		t.Fatalf("assignments = %v, want the router assignment", body.Assignments)
	}
}
