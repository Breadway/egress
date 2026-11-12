package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestProfileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "split-test.json")
	now := time.Now()

	p := NewProfile("NCC|10.179.160.1")
	p.RecordProbe("discord.com", EvidenceTLSStall, true, now)
	p.RecordProbe("discord.com", EvidenceTLSStall, true, now)
	p.RecordProbe("github.com", EvidenceNone, false, now)
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}

	got, err := LoadProfile(path, "NCC|10.179.160.1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State("discord.com", now) != StateBlocked {
		t.Errorf("discord should be blocked, got %s", got.State("discord.com", now))
	}
	if got.State("github.com", now) != StateAllowed {
		t.Errorf("github should be allowed, got %s", got.State("github.com", now))
	}
	if got.Entries["discord.com"].Evidence != EvidenceTLSStall {
		t.Errorf("evidence not stored: %q", got.Entries["discord.com"].Evidence)
	}
}

func TestProfileRequiresTwoFailures(t *testing.T) {
	now := time.Now()
	p := NewProfile("net")
	p.RecordProbe("discord.com", EvidenceTLSStall, true, now)
	if p.State("discord.com", now) == StateBlocked {
		t.Fatal("one failure must not block")
	}
	p.RecordProbe("discord.com", EvidenceTLSStall, true, now)
	if p.State("discord.com", now) != StateBlocked {
		t.Fatal("two failures must block")
	}
	// A success clears the streak and the blocked state.
	p.RecordProbe("discord.com", EvidenceNone, false, now)
	if p.State("discord.com", now) != StateAllowed {
		t.Fatal("success must clear blocked")
	}
}

func TestAllowedExpires(t *testing.T) {
	now := time.Now()
	p := NewProfile("net")
	p.RecordProbe("github.com", EvidenceNone, false, now)
	if p.State("github.com", now.Add(allowedTTL-time.Minute)) != StateAllowed {
		t.Fatal("allowed should hold inside the TTL")
	}
	if p.State("github.com", now.Add(allowedTTL+time.Minute)) != StateUnknown {
		t.Fatal("allowed should expire")
	}
}

func TestAddBlocked(t *testing.T) {
	now := time.Now()
	p := NewProfile("net")
	p.AddBlocked("discord.com", EvidenceSeed, now)
	if p.State("discord.com", now) != StateBlocked {
		t.Fatal("seed entry must be blocked")
	}
	if len(p.BlockedDomains(now)) != 1 {
		t.Fatal("blocked list should have one entry")
	}
}

func TestNetworkKeyAndPath(t *testing.T) {
	if got := NetworkKey("NCC", "10.179.160.1"); got != "NCC|10.179.160.1" {
		t.Errorf("network key: %q", got)
	}
	path := ProfilePath("NCC 4|10.179.160.1")
	if filepath.Base(path) != "split-NCC_4_10.179.160.1.json" {
		t.Errorf("profile path: %q", path)
	}
}

func TestClassifyProbeErrors(t *testing.T) {
	dial := []struct {
		name string
		err  error
		want DomainState
		ev   Evidence
	}{
		{"timeout", os.ErrDeadlineExceeded, StateBlocked, EvidenceConnectStall},
		{"refused", syscall.ECONNREFUSED, StateUnknown, EvidenceNone},
		{"other", errors.New("boom"), StateUnknown, EvidenceNone},
	}
	for _, tc := range dial {
		got, ev := classifyDialError(tc.err)
		if got != tc.want || ev != tc.ev {
			t.Errorf("dial %s: got (%s,%s), want (%s,%s)", tc.name, got, ev, tc.want, tc.ev)
		}
	}
	handshake := []struct {
		name string
		err  error
		want DomainState
		ev   Evidence
	}{
		{"cert", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, StateBlocked, EvidenceCertSubstitution},
		{"reset", syscall.ECONNRESET, StateBlocked, EvidenceTLSStall},
		{"deadline", os.ErrDeadlineExceeded, StateBlocked, EvidenceTLSStall},
		{"other", errors.New("boom"), StateUnknown, EvidenceNone},
	}
	for _, tc := range handshake {
		got, ev := classifyTLSError(tc.err)
		if got != tc.want || ev != tc.ev {
			t.Errorf("tls %s: got (%s,%s), want (%s,%s)", tc.name, got, ev, tc.want, tc.ev)
		}
	}
}

func TestHeadStatus(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
	}()
	status, err := headStatus(client, "example.com", "test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if status != 403 {
		t.Errorf("status %d, want 403", status)
	}
}

func TestProbeResolveFailureIsTransient(t *testing.T) {
	res := ProbeDomain(context.Background(), "example.invalid", ProbeOptions{
		Resolve: func(ctx context.Context, name string) ([]net.IP, error) {
			return nil, errors.New("no such host")
		},
	})
	if !res.Transient || res.State == StateBlocked {
		t.Errorf("resolve failure must be transient, got %+v", res)
	}
}
