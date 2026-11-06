package main

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

// TestDoHHandleTCPFraming proves the 2-byte length-prefix framing round-trips
// over loopback without touching the network: the stub lookup echoes.
func TestDoHHandleTCPFraming(t *testing.T) {
	r := newDoHResolver("", log.New(os.Stderr, "test: ", 0))
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	r.lookup = func(context.Context, []byte) ([]byte, error) { return want, nil }

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { r.handleTCP(server); close(done) }()

	query := []byte{0x01, 0x02, 0x03}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	var rhdr [2]byte
	if _, err := io.ReadFull(client, rhdr[:]); err != nil {
		t.Fatal(err)
	}
	if got := int(binary.BigEndian.Uint16(rhdr[:])); got != len(want) {
		t.Fatalf("response length = %d, want %d", got, len(want))
	}
	resp := make([]byte, len(want))
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatal(err)
	}
	for i := range want {
		if resp[i] != want[i] {
			t.Fatalf("response = %x, want %x", resp, want)
		}
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("handleTCP did not exit after client close")
	}
}
