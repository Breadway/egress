package main

import (
	"errors"
	"net"
	"testing"
)

type identityFake struct {
	platform
	pubkey string
	pubErr error
}

func (f identityFake) LivePublicKey() (string, error) {
	if f.pubErr != nil {
		return "", f.pubErr
	}
	return f.pubkey, nil
}

// loopbackName finds an interface carrying 127.0.0.1, for tests that need a
// real address without touching the tunnel.
func loopbackName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if interfaceHasIP(iface.Name, "127.0.0.1") {
			return iface.Name
		}
	}
	t.Fatal("no interface carries 127.0.0.1")
	return ""
}

// TestInterfaceHasIP proves the address half of the identity check.
func TestInterfaceHasIP(t *testing.T) {
	iface := loopbackName(t)
	if !interfaceHasIP(iface, "127.0.0.1") {
		t.Errorf("%s should carry 127.0.0.1", iface)
	}
	if interfaceHasIP(iface, "192.0.2.1") {
		t.Errorf("%s must not claim TEST-NET-1", iface)
	}
	if interfaceHasIP("does-not-exist-0", "127.0.0.1") {
		t.Error("missing interface must not match")
	}
}

// TestCheckTunnelIdentity proves a mismatched live key fails the install
// gate instead of verifying the wrong identity.
func TestCheckTunnelIdentity(t *testing.T) {
	iface := loopbackName(t)
	const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const other = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	want, err := publicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := publicKey(other)
	if err != nil {
		t.Fatal(err)
	}
	base := tunnelConfig{PrivateKey: key, ClientIP: "127.0.0.1"}

	if err := checkTunnelIdentityIface(identityFake{pubkey: want}, iface, base); err != nil {
		t.Errorf("matching identity must pass: %v", err)
	}
	if err := checkTunnelIdentityIface(identityFake{}, iface, base); err != nil {
		t.Errorf("unreportable key (windows) must pass on address alone: %v", err)
	}
	if err := checkTunnelIdentityIface(identityFake{pubkey: otherPub}, iface, base); err == nil {
		t.Error("mismatched live key must fail")
	}
	wrongAddr := base
	wrongAddr.ClientIP = "192.0.2.1"
	if err := checkTunnelIdentityIface(identityFake{pubkey: want}, iface, wrongAddr); err == nil {
		t.Error("missing address must fail")
	}
	if err := checkTunnelIdentityIface(identityFake{pubErr: errors.New("no wg")}, iface, base); err == nil {
		t.Error("unreadable live key must fail")
	}
}
