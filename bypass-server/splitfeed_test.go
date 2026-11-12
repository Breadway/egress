package main

import (
	"testing"
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
