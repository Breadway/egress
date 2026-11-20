package wgtunnel

import (
	"context"
	"log"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payloads := [][]byte{[]byte("wireguard datagram"), nil, make([]byte, 1400)}
	go func() {
		for _, p := range payloads {
			if err := WriteFrame(client, p); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	buf := make([]byte, MaxDatagram)
	for i, want := range payloads {
		got, err := ReadFrame(server, buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if len(got) != len(want) {
			t.Fatalf("frame %d: %d bytes, want %d", i, len(got), len(want))
		}
	}
}

// udpEcho answers every datagram with the same payload.
func udpEcho(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, MaxDatagram)
		for {
			n, addr, rerr := conn.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() }
}

// The upgrade path has to carry a real datagram end to end: client UDP socket,
// framed over a TCP upgrade, server, UDP echo, and back. This is the path
// WireGuard uses, minus the TLS wrapper that production adds.
func TestTunnelCarriesDatagrams(t *testing.T) {
	echoAddr, stopEcho := udpEcho(t)
	defer stopEcho()

	srv := httptest.NewServer(Handler(echoAddr, "/wg-tunnel"))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "test: ", 0)
	tun := NewWithOptions(Options{
		Local: "127.0.0.1:0",
		Host:  "127.0.0.1",
		Port:  u.Port(),
		Path:  "/wg-tunnel/test",
		Plain: true,
	}, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tun.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	defer tun.Stop()

	local, err := net.ResolveUDPAddr("udp", tun.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp", nil, local)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	payload := []byte("a wireguard handshake initiation")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, MaxDatagram)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no datagram came back through the relay: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("got %q, want %q", buf[:n], payload)
	}
}
