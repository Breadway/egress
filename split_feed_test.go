package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMergeFeedDomains(t *testing.T) {
	now := time.Now()
	p := NewProfile("net")
	p.AddBlocked("poki.com", EvidenceIPRejected, now)

	added := mergeFeedDomains(p, []feedDomain{
		{Domain: "Discord.com", Evidence: "tls-stall", Count: 3},
		{Domain: "poki.com", Evidence: "ip-rejected"},
		{Domain: "not a domain", Evidence: "tls-stall"},
		{Domain: "ipv4only.arpa", Evidence: "connect-stall"},
	}, now)
	if added != 1 {
		t.Fatalf("added %d, want 1", added)
	}
	if p.State("discord.com", now) != StateBlocked {
		t.Fatal("feed domain not blocked")
	}
	if p.Entries["discord.com"].Evidence != EvidenceFeed {
		t.Fatalf("evidence: %q", p.Entries["discord.com"].Evidence)
	}
	if mergeFeedDomains(p, []feedDomain{{Domain: "discord.com"}}, now) != 0 {
		t.Fatal("merge must be idempotent")
	}
}

func TestDeviceIDAtStable(t *testing.T) {
	dir := t.TempDir()
	first := deviceIDAt(dir)
	if len(first) != 32 {
		t.Fatalf("id length %d", len(first))
	}
	if second := deviceIDAt(dir); second != first {
		t.Fatalf("id changed: %q then %q", first, second)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "device-id")); err != nil || len(data) == 0 {
		t.Fatalf("id file: %v", err)
	}
}

func TestPlausibleDomain(t *testing.T) {
	good := []string{"discord.com", "store.steampowered.com", "x.com"}
	for _, d := range good {
		if !plausibleDomain(d) {
			t.Errorf("%q should be plausible", d)
		}
	}
	bad := []string{"", "nodot", "has space.com", "http://x.com", "*.example.com"}
	for _, d := range bad {
		if plausibleDomain(d) {
			t.Errorf("%q should be rejected", d)
		}
	}
}

func TestReporterFlush(t *testing.T) {
	var got splitReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	r := newSplitReporter("net|10.0.0.1", t.TempDir(), log.New(testWriter{t}, "", 0))
	r.SetMergeFunc(func([]feedDomain) {})
	r.reportURL = srv.URL
	r.Report("discord.com", EvidenceTLSStall)
	r.Report("poki.com", EvidenceIPRejected)
	if err := r.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Device == "" || got.Network != "net|10.0.0.1" || len(got.Domains) != 2 {
		t.Fatalf("payload: %+v", got)
	}
	if r.pending() != 0 {
		t.Fatalf("queue not cleared: %d", r.pending())
	}
}

func TestReporterFeedFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("network") != "net|10.0.0.1" {
			t.Errorf("network query: %q", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(feedResponse{Version: 1, Domains: []feedDomain{
			{Domain: "discord.com", Evidence: "tls-stall"},
		}})
	}))
	defer srv.Close()

	r := newSplitReporter("net|10.0.0.1", t.TempDir(), log.New(testWriter{t}, "", 0))
	r.seedURL = srv.URL
	var merged []feedDomain
	r.SetMergeFunc(func(domains []feedDomain) { merged = domains })
	r.fetchFeed(context.Background())
	if len(merged) != 1 || merged[0].Domain != "discord.com" {
		t.Fatalf("merged: %+v", merged)
	}
}
