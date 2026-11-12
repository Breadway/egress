package main

import (
	"log"
	"net"
	"testing"
	"time"
)

// buildAnswer builds a minimal A response for example.com with two A records
// and a CNAME before them, to exercise name skipping.
func buildAnswer() []byte {
	var b []byte
	b = append(b, 0x12, 0x34, 0x81, 0x80) // id, flags
	b = append(b, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00)
	// question: example.com A IN
	b = append(b, 7)
	b = append(b, []byte("example")...)
	b = append(b, 3)
	b = append(b, []byte("com")...)
	b = append(b, 0, 0, 1, 0, 1)
	// CNAME www.example.com
	b = append(b, 3)
	b = append(b, []byte("www")...)
	b = append(b, 0xc0, 0x0c)
	b = append(b, 0, 5, 0, 1, 0, 0, 0x01, 0x2c, 0, 6)
	b = append(b, 3)
	b = append(b, []byte("cdn")...)
	b = append(b, 0xc0, 0x0c)
	// A 93.184.216.34 ttl 300
	b = append(b, 0xc0, 0x2b) // pointer to www
	b = append(b, 0, 1, 0, 1, 0, 0, 0x01, 0x2c, 0, 4, 93, 184, 216, 34)
	return b
}

func TestDNSQueryName(t *testing.T) {
	query := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if got := dnsQueryName(query); got != "example.com" {
		t.Errorf("query name: %q", got)
	}
	if got := dnsQueryName(nil); got != "" {
		t.Errorf("nil query should be empty, got %q", got)
	}
}

func TestDNSAnswerIPv4(t *testing.T) {
	resp := buildAnswer()
	ips, ttl := dnsAnswerIPv4(resp)
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("ips: %v", ips)
	}
	if ttl != 300*time.Second {
		t.Errorf("ttl: %v", ttl)
	}
}

func TestRouteManagerAddCleanup(t *testing.T) {
	var calls [][]string
	rm := &routeManager{
		dev:    "wg0",
		log:    log.New(testWriter{t}, "", 0),
		routes: map[string]time.Time{},
		run: func(args ...string) error {
			calls = append(calls, args)
			return nil
		},
	}
	now := time.Now()
	rm.Add([]net.IP{net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8)}, 0, now)
	if rm.Count() != 2 {
		t.Fatalf("count: %d", rm.Count())
	}
	if len(calls) != 2 || calls[0][0] != "route" || calls[0][1] != "replace" {
		t.Fatalf("calls: %v", calls)
	}
	rm.Cleanup(now.Add(routeMinTTL + time.Minute))
	if rm.Count() != 0 {
		t.Fatalf("routes survived cleanup: %d", rm.Count())
	}
}

func TestSplitControllerRoutesBlockedDomain(t *testing.T) {
	var calls [][]string
	rm := &routeManager{
		dev:    "wg0",
		log:    log.New(testWriter{t}, "", 0),
		routes: map[string]time.Time{},
		run: func(args ...string) error {
			calls = append(calls, args)
			return nil
		},
	}
	c := newSplitController("testnet", "wlan0", rm, log.New(testWriter{t}, "", 0))
	now := time.Now()
	c.profile = NewProfile("testnet")
	c.profile.AddBlocked("discord.com", EvidenceSeed, now)

	c.HandleAnswer("discord.com", []net.IP{net.IPv4(162, 159, 136, 232)}, 2*time.Minute)
	if rm.Count() != 1 {
		t.Fatalf("blocked answer did not route: %v", calls)
	}
	if len(calls) != 1 || calls[0][1] != "replace" {
		t.Fatalf("calls: %v", calls)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
