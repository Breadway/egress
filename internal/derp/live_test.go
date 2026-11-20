package derp

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"
)

// TestLiveRelay is the check the fake relay cannot make: that the frames,
// sealed handshake and AppName are accepted by the public relay and that two
// independently connected keys can reach each other.
//
// It is opt-in because it uses shared infrastructure:
//
//	EGRESS_DERP_LIVE=1 go test ./internal/derp -run TestLiveRelay -v
func TestLiveRelay(t *testing.T) {
	if os.Getenv("EGRESS_DERP_LIVE") == "" {
		t.Skip("set EGRESS_DERP_LIVE=1 to use the public relay")
	}
	relay := Relay{Host: "derp5e.tailscale.com", Port: "443", Region: "syd"}
	aCh := make(chan []byte, 4)
	bCh := make(chan []byte, 4)
	a := liveClient(t, relay, aCh)
	defer a.Close()
	b := liveClient(t, relay, bCh)
	defer b.Close()

	first := []byte("egress derp live check A to B")
	// The relay registers each key when it reads ClientInfo; give the second
	// connection a moment so the first send is not silently dropped.
	time.Sleep(1500 * time.Millisecond)
	if err := a.Send(b.PublicKey(), first); err != nil {
		t.Fatalf("A send: %v (connection error: %v)", err, a.Err())
	}
	select {
	case got := <-bCh:
		if !bytes.Equal(got, first) {
			t.Fatalf("B got %q", got)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("B did not receive A's packet")
	}

	second := []byte("egress derp live check B to A")
	if err := b.Send(a.PublicKey(), second); err != nil {
		t.Fatalf("B send: %v", err)
	}
	select {
	case got := <-aCh:
		if !bytes.Equal(got, second) {
			t.Fatalf("A got %q", got)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("A did not receive B's packet")
	}
}

func liveClient(t *testing.T, relay Relay, packets chan<- []byte) *Client {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := Dial(ctx, Options{
		Relay:   relay,
		Private: priv,
		Version: "live-test",
		OnPacket: func(src [32]byte, pkt []byte) {
			select {
			case packets <- append([]byte(nil), pkt...):
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("dial %s: %v", relay.Host, err)
	}
	return c
}
