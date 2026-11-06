package main

import (
	"context"
	"encoding/binary"
	"log"
	"os"
	"strings"
	"testing"
)

func ednsQuery(adSize int) []byte {
	// Header: 1 question, 1 additional. QNAME example.com, A/IN.
	q := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	for _, l := range []string{"example", "com"} {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0x00, 0x00, 0x01, 0x00, 0x01)
	// OPT: root name, type 41, advertised size, TTL, RDLEN 0.
	q = append(q, 0x00, 0x00, 0x29)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(adSize))
	q = append(q, tmp[:]...)
	q = append(q, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	return q
}

func TestEdnsUDPSize(t *testing.T) {
	if got := ednsUDPSize(ednsQuery(4096)); got != 4096 {
		t.Errorf("advertised 4096, got %d", got)
	}
	// Same query with ARCOUNT patched to 0 and the OPT record cut: the
	// question is 12 header + 13 name + 4 type/class = 29 bytes.
	q := ednsQuery(4096)
	q[11] = 0
	if got := ednsUDPSize(q[:29]); got != 512 {
		t.Errorf("no OPT, got %d, want 512", got)
	}
	for _, garbage := range [][]byte{nil, {0x00}, make([]byte, 11), {0x12, 0x34, 0x01}} {
		if got := ednsUDPSize(garbage); got != 512 {
			t.Errorf("garbage %d bytes: got %d, want 512", len(garbage), got)
		}
	}
	// Absurdly small advertisement floors at 512.
	if got := ednsUDPSize(ednsQuery(128)); got != 512 {
		t.Errorf("tiny advertisement: got %d, want 512", got)
	}
}

func TestTruncateUDP(t *testing.T) {
	header := make([]byte, 12)
	header[2] = 0x81
	header[3] = 0x80
	short := append(append([]byte(nil), header...), 0x01, 0x02)
	if got := truncateUDP(short, 512); string(got) != string(short) {
		t.Error("short response must pass through untouched")
	}
	long := append(append([]byte(nil), header...), make([]byte, 600)...)
	got := truncateUDP(long, 512)
	if len(got) != 512 {
		t.Fatalf("cut length = %d, want 512", len(got))
	}
	if got[2]&0x02 == 0 {
		t.Error("TC bit must be set on a cut response")
	}
	if !strings.HasPrefix(string(got), string(header[:2])) {
		t.Error("ID must survive truncation")
	}
}

func TestRefreshKeepsSeedWithoutGateway(t *testing.T) {
	r := newDoHResolver("", log.New(os.Stderr, "test: ", 0))
	r.mu.Lock()
	r.addrs = []string{"9.9.9.9"}
	r.mu.Unlock()
	if err := r.refresh(context.Background()); err != nil {
		t.Fatalf("gateway-less refresh must keep the seed, got %v", err)
	}
	got := r.targets()
	if len(got) != 1 || got[0] != "9.9.9.9" {
		t.Errorf("addrs = %v, want the seeded address kept", got)
	}
}
