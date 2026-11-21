package doh

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

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

// cannedAnswer fabricates a valid A answer from a query. The framing tests do
// not need a real upstream, and using one made CI depend on outbound DoH.
func cannedAnswer(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("short DNS query")
	}
	resp := make([]byte, 12, 12+len(query)-12+16)
	copy(resp[0:2], query[0:2])
	resp[2] = 0x81 // response, recursion desired
	resp[3] = 0x80 // recursion available, no error
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], 1)
	resp = append(resp, query[12:]...)
	resp = append(resp,
		0xC0, 0x0C, // pointer to the question name
		0x00, 0x01, 0x00, 0x01, // A, IN
		0x00, 0x00, 0x00, 0x3C, // 60 seconds
		0x00, 0x04, 203, 0, 113, 7)
	return resp, nil
}

func startTestResolver(t *testing.T) (string, func()) {
	t.Helper()

	resolver := New("", log.New(io.Discard, "", 0))
	resolver.listenAddr = "127.0.0.1:0"
	resolver.lookup = func(_ context.Context, query []byte) ([]byte, error) {
		return cannedAnswer(query)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = resolver.Serve(ctx)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		addr := resolver.LocalAddr()
		if addr != "" {
			if conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
				conn.Close()
				return addr, func() {
					cancel()
					<-done
				}
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

// TestDoHHandleTCPFraming proves the 2-byte length-prefix framing round-trips
// over loopback without touching the network: the stub lookup echoes.
func TestDoHHandleTCPFraming(t *testing.T) {
	r := New("", log.New(os.Stderr, "test: ", 0))
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
	if got := TruncateUDP(short, 512); string(got) != string(short) {
		t.Error("short response must pass through untouched")
	}
	long := append(append([]byte(nil), header...), make([]byte, 600)...)
	got := TruncateUDP(long, 512)
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
	r := New("", log.New(os.Stderr, "test: ", 0))
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

func TestMergeAddresses(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		seed string
		want []string
	}{
		{"seed only", nil, "152.69.174.7", []string{"152.69.174.7"}},
		{"seed already there", []string{"152.69.174.7"}, "152.69.174.7", []string{"152.69.174.7"}},
		{"seed appended", []string{"203.0.113.9"}, "152.69.174.7", []string{"203.0.113.9", "152.69.174.7"}},
		{"dedupe", []string{"203.0.113.9", "203.0.113.9"}, "152.69.174.7", []string{"203.0.113.9", "152.69.174.7"}},
	}
	for _, tc := range cases {
		got := mergeAddresses(tc.in, tc.seed)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}
