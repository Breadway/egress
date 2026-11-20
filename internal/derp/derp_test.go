package derp

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type fakeRelay struct {
	t          *testing.T
	srv        *httptest.Server
	serverPriv [32]byte
	serverPub  [32]byte
	mu         sync.Mutex
	appName    string
	gotPacket  chan []byte
	gotSource  [32]byte
}

func newFakeRelay(t *testing.T) *fakeRelay {
	t.Helper()
	f := &fakeRelay{t: t, gotPacket: make(chan []byte, 4)}
	if _, err := rand.Read(f.serverPriv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(f.serverPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(f.serverPub[:], pub)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	f.t = t
	f.srv = srv
	return f
}

func (f *fakeRelay) relay() Relay {
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(f.srv.URL, "https://"))
	return Relay{Host: host, Port: port, Region: "test"}
}

func (f *fakeRelay) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/derp" || !strings.EqualFold(r.Header.Get("Upgrade"), "DERP") {
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		f.t.Error("no hijacker")
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		f.t.Errorf("hijack: %v", err)
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nDerp-Version: 2\r\nDerp-Public-Key: %s\r\n\r\n", hex.EncodeToString(f.serverPub[:]))

	br := brw.Reader
	// FrameClientInfo: 32-byte key + nonce + naclbox(JSON).
	typ, n, err := readFrameHeader(br)
	if err != nil {
		return
	}
	if typ != frameClientInfo {
		f.t.Errorf("first frame = %#x, want ClientInfo", typ)
		return
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		return
	}
	if len(payload) < 32+24 {
		f.t.Errorf("short ClientInfo")
		return
	}
	var clientPub [32]byte
	copy(clientPub[:], payload[:32])
	var nonce [24]byte
	copy(nonce[:], payload[32:56])
	plain, ok := box.Open(nil, payload[56:], &nonce, &clientPub, &f.serverPriv)
	if !ok {
		f.t.Error("ClientInfo did not open")
		return
	}
	var info struct {
		Version     int
		CanAckPings bool
		AppName     string
	}
	if err := json.Unmarshal(plain, &info); err != nil {
		f.t.Errorf("ClientInfo JSON: %v", err)
		return
	}
	f.mu.Lock()
	f.appName = info.AppName
	f.mu.Unlock()

	var dstKey [32]byte
	copy(dstKey[:], "01234567890123456789012345678901")
	for {
		typ, n, err := readFrameHeader(br)
		if err != nil {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}
		switch typ {
		case frameSendPacket:
			if len(payload) < 32 {
				continue
			}
			f.mu.Lock()
			copy(f.gotSource[:], payload[:32])
			f.mu.Unlock()
			f.gotPacket <- payload[32:]
			// Echo it back with the destination key as the source, which is
			// how a real relay delivers to a connected peer.
			reply := make([]byte, 0, 32+len(payload)-32)
			reply = append(reply, payload[:32]...)
			reply = append(reply, payload[32:]...)
			if err := writeTestFrame(conn, frameRecvPacket, reply); err != nil {
				return
			}
		case framePing:
			_ = writeTestFrame(conn, framePong, payload)
		case frameKeepAlive:
		}
	}
}

// srv is filled in after StartTLS; declared separately to keep the struct
// literal above readable.
func (f *fakeRelay) server() *httptest.Server { return f.srv }

func writeTestFrame(w io.Writer, typ byte, payload []byte) error {
	hdr := make([]byte, frameHeaderLen)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func TestClientHandshakeAndRelay(t *testing.T) {
	f := newFakeRelay(t)
	cert := f.server().Certificate()
	pool := x509Pool(t, cert)

	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 4)
	var gotSrc [32]byte
	client, err := Dial(context.Background(), Options{
		Relay:   f.relay(),
		Private: private,
		RootCAs: pool,
		OnPacket: func(src [32]byte, pkt []byte) {
			gotSrc = src
			got <- append([]byte(nil), pkt...)
		},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var dst [32]byte
	copy(dst[:], "01234567890123456789012345678901")
	payload := []byte("wireguard-shaped bytes")
	if err := client.Send(dst, payload); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case relayed := <-f.gotPacket:
		if string(relayed) != string(payload) {
			t.Fatalf("relay got %q", relayed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not receive the packet")
	}
	select {
	case back := <-got:
		if string(back) != string(payload) {
			t.Fatalf("client got %q", back)
		}
		if gotSrc != dst {
			t.Fatalf("source key not preserved")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not receive the echoed packet")
	}
	// The relay reads ClientInfo before the first packet, so by now the app
	// name has been observed.
	f.mu.Lock()
	app := f.appName
	f.mu.Unlock()
	if app != AppName {
		t.Fatalf("AppName = %q, want %q", app, AppName)
	}
}

func x509Pool(t *testing.T, cert *x509.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
