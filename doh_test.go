package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPublicKeyVector(t *testing.T) {
	const private = "MCqypbvCdUOQ3YIitFcch4jsAbxw75Kpr2YWm18KXW4="
	const public = "FIE3IB/8DltS0rF7sywrFM9mCm+svM3sw0SwYWqVWB8="

	got, err := publicKey(private)
	if err != nil {
		t.Fatalf("publicKey: %v", err)
	}
	if got != public {
		t.Fatalf("publicKey = %s, want %s", got, public)
	}
}

func TestNormalizeKey(t *testing.T) {
	const valid = "MCqypbvCdUOQ3YIitFcch4jsAbxw75Kpr2YWm18KXW4="

	if got, err := normalizeKey("  " + valid + "\n"); err != nil || got != valid {
		t.Fatalf("valid key: got %q, %v", got, err)
	}

	cases := map[string]string{
		"empty":      "",
		"short":      "abcd",
		"bad base64": strings.Repeat("!", 44),
		"31 bytes":   base64.StdEncoding.EncodeToString(make([]byte, 31)),
		"33 bytes":   base64.StdEncoding.EncodeToString(make([]byte, 33)),
	}
	for name, key := range cases {
		if _, err := normalizeKey(key); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestGrade(t *testing.T) {
	cases := []struct {
		name string
		r    checkResults
		want string
	}{
		{"all ok", checkResults{Tunnel: "up", Probe: "ok", Exit: aegisIPv4}, "functional"},
		{"dns only", checkResults{Tunnel: "skipped", Probe: "skipped"}, "functional"},
		{"tunnel down", checkResults{Tunnel: "down", Probe: "failed", Exit: "no result"}, "partial"},
		{"wrong exit", checkResults{Tunnel: "up", Probe: "ok", Exit: "got 1.2.3.4, expected " + aegisIPv4}, "partial"},
		{"dns down", checkResults{DNS: "i/o timeout", Tunnel: "down", Probe: "failed", Exit: "no result"}, "failed"},
	}
	for _, c := range cases {
		if got := c.r.grade(); got != c.want {
			t.Errorf("%s: grade = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRenderedConfig(t *testing.T) {
	cfg := renderWGConfig(tunnelConfig{
		ClientIP:   "10.88.0.4",
		PrivateKey: "MCqypbvCdUOQ3YIitFcch4jsAbxw75Kpr2YWm18KXW4=",
		Endpoint:   "152.69.174.7:7105",
	})

	for _, want := range []string{
		"Address = 10.88.0.4/32",
		"PrivateKey = MCqypbvCdUOQ3YIitFcch4jsAbxw75Kpr2YWm18KXW4=",
		"PublicKey = " + aegisPublicKey,
		"Endpoint = 152.69.174.7:7105",
		"dev %i",
		"Table = off",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config is missing %q:\n%s", want, cfg)
		}
	}
}

func dnsQuery(id uint16, name string) []byte {
	b := make([]byte, 0, 64)
	b = binary.BigEndian.AppendUint16(b, id)
	b = binary.BigEndian.AppendUint16(b, 0x0100) // recursion desired
	b = binary.BigEndian.AppendUint16(b, 1)      // qdcount
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 1) // A
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	return b
}

func checkAnswer(t *testing.T, id uint16, resp []byte) {
	t.Helper()
	if len(resp) < 12 {
		t.Fatalf("response is %d bytes", len(resp))
	}
	if got := binary.BigEndian.Uint16(resp[0:2]); got != id {
		t.Fatalf("id = %#x, want %#x", got, id)
	}
	if rcode := resp[3] & 0x0f; rcode != 0 {
		t.Fatalf("rcode = %d", rcode)
	}
	if answers := binary.BigEndian.Uint16(resp[6:8]); answers == 0 {
		t.Fatal("response has no answers")
	}
}

func startTestResolver(t *testing.T) (string, func()) {
	t.Helper()

	addr := "127.0.0.1:15353"
	resolver := newDoHResolver("", log.New(io.Discard, "", 0))
	resolver.listenAddr = addr

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = resolver.serve(ctx)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return addr, func() {
				cancel()
				<-done
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("resolver did not start")
	return "", nil
}

func TestResolverUDP(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the DoH endpoint")
	}
	addr, stop := startTestResolver(t)
	defer stop()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	const id = 0x1234
	if _, err := conn.Write(dnsQuery(id, "example.com")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	checkAnswer(t, id, buf[:n])
}

func TestResolverTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the DoH endpoint")
	}
	addr, stop := startTestResolver(t)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	const id = 0x4321
	query := dnsQuery(id, "example.com")

	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(query)))
	if _, err := conn.Write(append(prefix[:], query...)); err != nil {
		t.Fatal(err)
	}

	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatal(err)
	}
	size := int(binary.BigEndian.Uint16(prefix[:]))
	resp := make([]byte, size)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	checkAnswer(t, id, resp)
}

func TestSameRouteSet(t *testing.T) {
	a := []Route{{Iface: "eth0", Gateway: "192.168.1.1"}, {Iface: "wlan0", Gateway: "192.168.1.1"}}
	b := []Route{{Iface: "wlan0", Gateway: "192.168.1.1"}, {Iface: "eth0", Gateway: "192.168.1.1"}}
	if !sameRouteSet(a, b) {
		t.Error("same routes in different order should match")
	}
	if sameRouteSet(a, a[:1]) {
		t.Error("different sizes should not match")
	}
	if sameRouteSet(a, []Route{{Iface: "eth0", Gateway: "10.0.0.1"}, {Iface: "wlan0", Gateway: "192.168.1.1"}}) {
		t.Error("different gateways should not match")
	}
	if !sameRouteSet(nil, nil) {
		t.Error("two empty sets should match")
	}
	dup := []Route{{Iface: "eth0", Gateway: "1.1.1.1"}, {Iface: "eth0", Gateway: "1.1.1.1"}}
	if !sameRouteSet(dup, append([]Route(nil), dup...)) {
		t.Error("identical duplicates should match")
	}
	if sameRouteSet(dup, dup[:1]) {
		t.Error("duplicate count must matter")
	}
}

func TestDohStagesDescribe(t *testing.T) {
	cases := []struct {
		stages dohStages
		want   string
	}{
		{dohStages{}, "no TCP connection"},
		{dohStages{reused: true}, "reused connection died"},
		{dohStages{tcp: true}, "TCP connected, TLS stalled"},
		{dohStages{tcp: true, tls: true}, "TLS done, no response"},
		{dohStages{tcp: true, tls: true, http: true}, "server answered, body failed"},
	}
	for _, c := range cases {
		if got := c.stages.describe(); got != c.want {
			t.Errorf("describe = %q, want %q", got, c.want)
		}
	}
}
