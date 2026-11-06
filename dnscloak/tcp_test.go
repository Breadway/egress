package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func buildQuery(name string, qtype uint16) []byte {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0x00)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1)
	return append(query, tail[:]...)
}

// TestHandleTCPCloaksRelay proves the TCP framing round-trips and cloaked
// names synthesize the relay address without forwarding upstream.
func TestHandleTCPCloaksRelay(t *testing.T) {
	s := &server{suffixes: []string{"example.com"}}

	query := buildQuery("host.example.com", 1)
	if got := s.handle(query); got == nil {
		t.Fatal("cloaked query must synthesize an answer")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go s.serveTCP(ln)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	var rhdr [2]byte
	if _, err := io.ReadFull(conn, rhdr[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, int(binary.BigEndian.Uint16(rhdr[:])))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) < 4 || string(resp[len(resp)-4:]) != string(net.ParseIP(relayIP).To4()) {
		t.Errorf("cloaked answer does not end with %s", relayIP)
	}
}

// TestParseQuestionRejectsGarbage proves malformed queries fall through to
// forwarding instead of panicking the handler.
func TestParseQuestionRejectsGarbage(t *testing.T) {
	for _, q := range [][]byte{nil, {0x00}, make([]byte, 12), {0x12, 0x34}} {
		if _, _, _, ok := parseQuestion(q); ok {
			t.Errorf("garbage %d bytes must not parse", len(q))
		}
	}
}
