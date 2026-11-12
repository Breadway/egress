package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestBlockedDestination(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"100.64.0.1", "100.92.158.72", "169.254.1.1", "0.0.0.0",
		"198.18.0.1", "::1", "fe80::1", "fc00::1",
	}
	for _, raw := range blocked {
		if !blockedDestination(net.ParseIP(raw)) {
			t.Errorf("%s should be blocked", raw)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"}
	for _, raw := range allowed {
		if blockedDestination(net.ParseIP(raw)) {
			t.Errorf("%s should be allowed", raw)
		}
	}
}

func TestLoadAuth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth")
	if err := os.WriteFile(path, []byte("# comment\n\nsam:s3cret\nother:pass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	users, err := loadAuth(path)
	if err != nil {
		t.Fatal(err)
	}
	if users["sam"] != "s3cret" || users["other"] != "pass" || len(users) != 2 {
		t.Fatalf("users: %v", users)
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("nocolon\n"), 0600)
	if _, err := loadAuth(bad); err == nil {
		t.Fatal("malformed auth file must fail")
	}
}

func TestSOCKSConnectAndAuth(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); c.Close() }(conn)
		}
	}()
	_, portStr, _ := net.SplitHostPort(echo.Addr().String())
	portNum, _ := strconv.Atoi(portStr)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(portNum))

	r := newRelay(map[string]string{"sam": "s3cret"}, 5*time.Second)
	r.guard = func(net.IP) bool { return false }
	r.resolve = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
	}

	client, server := net.Pipe()
	defer client.Close()
	go r.handle(server)
	br := bufio.NewReader(client)

	writeAll(t, client, []byte{5, 1, 2})
	if got := readN(t, br, 2); got[0] != 5 || got[1] != 2 {
		t.Fatalf("method reply: %v", got)
	}
	writeAll(t, client, []byte{1, 3, 's', 'a', 'm', 6, 's', '3', 'c', 'r', 'e', 't'})
	if got := readN(t, br, 2); got[1] != 0 {
		t.Fatalf("auth reply: %v", got)
	}
	writeAll(t, client, []byte{5, 1, 0, 1, 127, 0, 0, 1, port[0], port[1]})
	reply := readN(t, br, 10)
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("connect reply: %v", reply)
	}
	writeAll(t, client, []byte("hello"))
	if got := string(readN(t, br, 5)); got != "hello" {
		t.Fatalf("echo: %q", got)
	}
}

func TestSOCKSRejectsBadPassword(t *testing.T) {
	r := newRelay(map[string]string{"sam": "right"}, time.Second)
	client, server := net.Pipe()
	defer client.Close()
	go r.handle(server)
	br := bufio.NewReader(client)

	writeAll(t, client, []byte{5, 1, 2})
	_ = readN(t, br, 2)
	writeAll(t, client, []byte{1, 3, 's', 'a', 'm', 5, 'w', 'r', 'o', 'n', 'g'})
	if got := readN(t, br, 2); got[1] != 1 {
		t.Fatalf("auth must fail: %v", got)
	}
}

func TestGuardRejectsPrivateConnect(t *testing.T) {
	r := newRelay(map[string]string{"u": "p"}, time.Second)
	r.resolve = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
	}
	if _, err := r.connect("localhost:80"); err == nil {
		t.Fatal("loopback must be refused by the default guard")
	}
}

func writeAll(t *testing.T, w io.Writer, data []byte) {
	t.Helper()
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

func TestLimiterPaces(t *testing.T) {
	l := newLimiter(1000) // 1 KB/s, burst 250 B
	start := time.Now()
	l.reserve(1250) // burst plus one second of tokens
	if d := time.Since(start); d < 700*time.Millisecond {
		t.Fatalf("reserve returned after %v; the bucket did not pace", d)
	}
	if newLimiter(0) != nil {
		t.Error("zero rate should disable the limiter")
	}
}
