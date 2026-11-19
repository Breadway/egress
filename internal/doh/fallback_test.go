package doh

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TestFallbackAnswersWhenPrimaryFails proves the chain: when the Aegis resolver
// is unreachable the public fallback still answers, which is the difference
// between "no internet" and "working, unfiltered".
func TestFallbackAnswersWhenPrimaryFails(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	r := New("192.0.2.1", log.New(io.Discard, "", 0))
	fb := &fallback{url: srv.URL, host: "fallback.test", client: srv.Client()}
	r.fallbacks = []*fallback{fb}

	query := dnsQuery(0x1234, "example.com")
	resp, err := r.exchangeFallbacks(context.Background(), query)
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0x1234 {
		t.Errorf("id = %#x, want 0x1234", got)
	}
}

// TestFallbackCooldownSkipsDeadServer proves a failed fallback is skipped for a
// while, so a broken public resolver costs one timeout rather than one per
// query.
func TestFallbackCooldownSkipsDeadServer(t *testing.T) {
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()

	r := New("192.0.2.1", log.New(io.Discard, "", 0))
	r.fallbacks = []*fallback{{url: srv.URL, host: "dead.test", client: srv.Client()}}

	q := dnsQuery(1, "example.com")
	if _, err := r.exchangeFallbacks(context.Background(), q); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := r.exchangeFallbacks(context.Background(), q); err == nil {
		t.Fatal("expected failure")
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1 (cooldown)", hits)
	}
	_ = os.Stderr
	_ = time.Now
}
