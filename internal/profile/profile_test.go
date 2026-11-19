package profile

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := New("will-laptop")
	p.Relay = Relay{User: "dev-10-88-0-24", Pass: "secret"}
	p.DoH = DoH{Fallbacks: "cloudflare-dns.com=1.1.1.1"}

	signed, err := Sign(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Any change to the payload must invalidate it.
	tampered := signed
	tampered.Relay.Pass = "other"
	if err := Verify(tampered, pub); err == nil {
		t.Fatal("tampered profile verified")
	}

	// A different key must not verify either.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify(signed, otherPub); err == nil {
		t.Fatal("profile verified under the wrong key")
	}

	if err := Verify(Profile{Version: 99, Signature: signed.Signature}, pub); err == nil ||
		!strings.Contains(err.Error(), "schema") {
		t.Fatalf("unknown schema error = %v", err)
	}
}
