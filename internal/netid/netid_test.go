package netid

import (
	"path/filepath"
	"testing"
	"time"
)

func rawNetwork(gateway, mac string) Raw {
	return Raw{
		SSID:       "NCC",
		DNSSuffix:  "school.example",
		GatewayMAC: mac,
		GatewayIP:  gateway,
		Subnet:     "10.179.160.0/24",
	}
}

func TestCanonicalIDSurvivesGatewayChange(t *testing.T) {
	a := Build(rawNetwork("10.179.160.1", "a2:05:d6:dc:bf:cb"))
	b := Build(rawNetwork("10.179.160.40", "a2:05:d6:dc:bf:cb"))
	if a.CanonicalID() == "" || a.CanonicalID() != b.CanonicalID() {
		t.Fatalf("canonical IDs differ across gateway change: %q vs %q", a.CanonicalID(), b.CanonicalID())
	}
}

func TestCanonicalIDSeparatesSameSSIDByGatewayMAC(t *testing.T) {
	a := Build(rawNetwork("10.179.160.1", "a2:05:d6:dc:bf:cb"))
	b := Build(rawNetwork("10.179.160.1", "aa:bb:cc:dd:ee:ff"))
	if a.CanonicalID() == b.CanonicalID() {
		t.Fatal("two gateways with the same SSID should not share an ID")
	}
}

func TestCanonicalIDPrefersMACOverSuffix(t *testing.T) {
	// The gateway is the site anchor. A platform that reads a different DHCP
	// suffix must not mint a second identity for the same router.
	a := Build(rawNetwork("10.179.160.1", "a2:05:d6:dc:bf:cb"))
	b := Build(Raw{SSID: "NCC", DNSSuffix: "ncc.internal", GatewayMAC: "a2:05:d6:dc:bf:cb"})
	if a.CanonicalID() != b.CanonicalID() {
		t.Fatalf("suffix changed the ID for one gateway: %q vs %q", a.CanonicalID(), b.CanonicalID())
	}
}

func TestCanonicalIDSeparatesSameSSIDBySuffixWithoutMAC(t *testing.T) {
	a := Build(Raw{SSID: "School", DNSSuffix: "site-a.example"})
	b := Build(Raw{SSID: "School", DNSSuffix: "site-b.example"})
	if a.CanonicalID() == "" || a.CanonicalID() == b.CanonicalID() {
		t.Fatalf("suffix did not separate sites: %q vs %q", a.CanonicalID(), b.CanonicalID())
	}
}

func TestCanonicalIDSSIDWithGatewayIsSharedAndSiteScoped(t *testing.T) {
	a := Build(Raw{SSID: "Cafe", GatewayIP: "192.168.1.1"})
	b := Build(Raw{SSID: "Cafe", GatewayIP: "192.168.1.1"})
	c := Build(Raw{SSID: "Cafe", GatewayIP: "10.0.0.1"})
	if a.CanonicalID() == "" || a.CanonicalID() != b.CanonicalID() {
		t.Fatalf("two devices on one link disagree: %q vs %q", a.CanonicalID(), b.CanonicalID())
	}
	if a.CanonicalID() == c.CanonicalID() {
		t.Fatal("the same SSID behind two gateways must not share an ID")
	}
}

func TestStoreKeepsSSIDOnlyIDAcrossGatewayChange(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)
	first, err := store.Resolve(Raw{SSID: "Cafe", GatewayIP: "192.168.1.1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Resolve(Raw{SSID: "Cafe", GatewayIP: "192.168.1.2"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("gateway change split an SSID-only network: %q -> %q", first.ID, second.ID)
	}
	if got := Build(Raw{SSID: "Cafe", GatewayIP: "192.168.1.2"}).CanonicalID(); got == "" {
		t.Fatal("expected a gateway-scoped fallback ID")
	}
}

func TestStoreResolvesGatewayChange(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Resolve(rawNetwork("10.179.160.1", "a2:05:d6:dc:bf:cb"), []string{"unknown|10.179.160.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Resolve(rawNetwork("10.179.160.40", "a2:05:d6:dc:bf:cb"), []string{"unknown|10.179.160.40"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("gateway change moved network %q -> %q", first.ID, second.ID)
	}
	if _, err := filepath.Abs(filepath.Join(dir, "networks.json")); err != nil {
		t.Fatal(err)
	}
}

func TestStoreKeepsIDWhenRouterChangesButSuffixMatches(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)
	first, err := store.Resolve(rawNetwork("10.179.160.1", "a2:05:d6:dc:bf:cb"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// New router, same SSID and DNS suffix. The strong ID changes, but the
	// saved network should be matched and the new ID kept as an alias.
	changed := rawNetwork("10.179.160.1", "aa:bb:cc:dd:ee:ff")
	second, err := store.Resolve(changed, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("router change split the network: %q -> %q", first.ID, second.ID)
	}
	newID := Build(changed).CanonicalID()
	found := false
	for _, alias := range second.Aliases {
		if alias == newID {
			found = true
		}
	}
	if !found {
		t.Fatalf("new canonical ID %q is not an alias: %v", newID, second.Aliases)
	}
}

func TestDefaultVerifyRejectsSameSSIDWithoutSeparator(t *testing.T) {
	rec := Record{Signals: Build(Raw{SSID: "School", DNSSuffix: "site-a.example"}).Hashes}
	cur := Build(Raw{SSID: "School", DNSSuffix: "site-b.example"})
	if DefaultVerify(rec, Raw{SSID: "School"}, cur) {
		t.Fatal("same SSID at two sites must not verify")
	}
}

func TestDefaultVerifyRejectsDifferentSSIDOnSharedSuffix(t *testing.T) {
	rec := Record{Signals: Build(Raw{SSID: "HomeA", DNSSuffix: "lan", GatewayMAC: "aa:aa:aa:aa:aa:aa"}).Hashes}
	cur := Build(Raw{SSID: "HomeB", DNSSuffix: "lan", GatewayMAC: "bb:bb:bb:bb:bb:bb"})
	if DefaultVerify(rec, Raw{SSID: "HomeB"}, cur) {
		t.Fatal("a shared generic suffix and two gateways must not merge")
	}
}

func TestDefaultVerifyAcceptsRenamedSSIDOnSameGateway(t *testing.T) {
	rec := Record{Signals: Build(Raw{SSID: "NCC", DNSSuffix: "ncc.wa.edu.au", GatewayMAC: "aa:aa:aa:aa:aa:aa"}).Hashes}
	cur := Build(Raw{SSID: "NCC-Students", DNSSuffix: "ncc.wa.edu.au", GatewayMAC: "aa:aa:aa:aa:aa:aa"})
	if !DefaultVerify(rec, Raw{SSID: "NCC-Students"}, cur) {
		t.Fatal("an SSID rename on the same gateway should keep the network")
	}
}

func TestHighestScoreWins(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)
	a, _ := store.Resolve(rawNetwork("10.0.0.1", "aa:aa:aa:aa:aa:aa"), nil, nil)
	// A different SSID and suffix, but the same weak subnet.
	b, err := store.Resolve(Raw{SSID: "Other", DNSSuffix: "other.example", GatewayMAC: "bb:bb:bb:bb:bb:bb", Subnet: "10.0.0.0/24"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.ID == a.ID {
		t.Fatal("different networks merged")
	}
	// Back to the first network; it must win on the strong score.
	c, err := store.Resolve(rawNetwork("10.0.0.1", "aa:aa:aa:aa:aa:aa"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != a.ID {
		t.Fatalf("first network lost its identity: %q -> %q", a.ID, c.ID)
	}
}

func TestStoreMergesLegacyAlias(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)
	// A profile written before the identity existed is found through its old
	// gateway key, and the alias survives for the shared feed.
	first, err := store.Resolve(rawNetwork("10.179.160.40", "a2:05:d6:dc:bf:cb"),
		[]string{"unknown|10.179.160.40", "NCC|10.179.160.40"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Resolve(Raw{SSID: "NCC", Subnet: "10.179.160.0/24"},
		[]string{"unknown|10.179.160.40"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("alias match moved network %q -> %q", first.ID, second.ID)
	}
	found := false
	for _, alias := range second.Aliases {
		if alias == "unknown|10.179.160.40" || alias == "NCC|10.179.160.40" {
			found = true
		}
	}
	if !found {
		t.Fatalf("legacy aliases were not kept: %v", second.Aliases)
	}
}

func TestFuzzyProbeFallsThroughToNextCandidate(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)
	raw := rawNetwork("10.179.160.1", "aa:aa:aa:aa:aa:aa")
	sig := Build(raw)
	// Two saved candidates share the same signals, as a failed probe would
	// have left them. The newer one is tried first and fails its probe; the
	// older one must still be reachable.
	store.data.Networks = []Record{
		{
			ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Signals: sig.Hashes,
			Fingerprint: "old", Probes: []Probe{{Domain: "good.example", Blocked: true}},
			LastSeen: time.Unix(100, 0).UTC(),
		},
		{
			ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Signals: sig.Hashes,
			Fingerprint: "older", Probes: []Probe{{Domain: "stale.example", Blocked: true}},
			LastSeen: time.Unix(200, 0).UTC(),
		},
	}
	// Change a weak signal so the exact fingerprint rows do not short-circuit.
	moved := raw
	moved.Subnet = "10.179.160.0/24"
	verify := ProbeVerify(func(domain string) (bool, bool) {
		return domain == "good.example", true
	})
	got, err := store.Resolve(moved, nil, verify)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("probe failure did not fall through: %q", got.ID)
	}
}

func TestExactSignalsSkipProbes(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)
	raw := rawNetwork("10.179.160.1", "a2:05:d6:dc:bf:cb")
	rec, err := store.Resolve(raw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetProbes(rec.ID, []Probe{{Domain: "blocked.example", Blocked: true}}); err != nil {
		t.Fatal(err)
	}
	// The probe now says the expectation is wrong. Identical signals are
	// still the same network, so the probe must not be consulted.
	verify := ProbeVerify(func(string) (bool, bool) { return false, true })
	again, err := store.Resolve(raw, nil, verify)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != rec.ID {
		t.Fatalf("an identical signal set was split by a probe: %q -> %q", rec.ID, again.ID)
	}
}

func TestProbeVerifyRequiresTwoMatches(t *testing.T) {
	rec := Record{
		Signals: Build(rawNetwork("10.179.160.1", "aa:aa:aa:aa:aa:aa")).Hashes,
		Probes: []Probe{
			{Domain: "a.example", Blocked: true},
			{Domain: "b.example", Blocked: true},
			{Domain: "c.example", Blocked: true},
		},
	}
	raw := rawNetwork("10.179.160.1", "aa:aa:aa:aa:aa:aa")
	sig := Build(raw)
	answers := map[string]bool{"a.example": true, "b.example": false, "c.example": true}
	verify := ProbeVerify(func(domain string) (bool, bool) {
		blocked, ok := answers[domain]
		return blocked, ok
	})
	if !verify(rec, raw, sig) {
		t.Fatal("two matching probes should verify")
	}
	answers["c.example"] = false
	if verify(rec, raw, sig) {
		t.Fatal("one matching probe out of three must not verify")
	}
}

func TestProbeVerifyAcceptsOneMatchingProbe(t *testing.T) {
	rec := Record{
		Signals: Build(rawNetwork("10.179.160.1", "aa:aa:aa:aa:aa:aa")).Hashes,
		Probes:  []Probe{{Domain: "a.example", Blocked: true}},
	}
	raw := rawNetwork("10.179.160.1", "aa:aa:aa:aa:aa:aa")
	if !ProbeVerify(func(string) (bool, bool) { return true, true })(rec, raw, Build(raw)) {
		t.Fatal("the only probe matched but the match was rejected")
	}
}

func TestProbeVerifyIgnoresInconclusive(t *testing.T) {
	rec := Record{
		Signals: Build(rawNetwork("10.179.160.1", "aa:aa:aa:aa:aa:aa")).Hashes,
		Probes:  []Probe{{Domain: "a.example", Blocked: true}},
	}
	raw := rawNetwork("10.179.160.1", "aa:aa:aa:aa:aa:aa")
	verify := ProbeVerify(func(string) (bool, bool) { return false, false })
	if !verify(rec, raw, Build(raw)) {
		t.Fatal("an inconclusive probe must not block the merge")
	}
}
