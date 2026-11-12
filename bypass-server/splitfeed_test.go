package main

import (
	"testing"
	"time"
)

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
