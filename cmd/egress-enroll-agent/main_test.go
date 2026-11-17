package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPub = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="

func validClaim() claim {
	return claim{
		ID:        "d-0123abcd",
		PubKey:    testPub,
		IP:        "10.88.0.42",
		RelayUser: "dev-10-88-0-42-0123abcd",
		RelayPass: "0123456789abcdefghijklmn",
	}
}

func TestValidate(t *testing.T) {
	if err := validate(validClaim()); err != nil {
		t.Fatalf("valid claim rejected: %v", err)
	}
	bad := []claim{
		func() claim { c := validClaim(); c.ID = "../etc"; return c }(),
		func() claim { c := validClaim(); c.PubKey = "short"; return c }(),
		func() claim { c := validClaim(); c.IP = "10.88.0.1"; return c }(),
		func() claim { c := validClaim(); c.IP = "192.168.1.5"; return c }(),
		func() claim { c := validClaim(); c.RelayUser = "dev-10-88-0-43-0123abcd"; return c }(),
		func() claim { c := validClaim(); c.RelayUser = "root"; return c }(),
		func() claim { c := validClaim(); c.RelayPass = "short"; return c }(),
		func() claim { c := validClaim(); c.RelayPass = "0123456789abcdefghi:jklmn"; return c }(),
	}
	for i, c := range bad {
		if err := validate(c); err == nil {
			t.Errorf("claim %d was accepted: %+v", i, c)
		}
	}
}

func TestParsePeers(t *testing.T) {
	conf := `[Interface]
PrivateKey = aaa

[Peer]
PublicKey = ` + testPub + `
AllowedIPs = 10.88.0.42/32

[Peer]
PublicKey = another
AllowedIPs = 10.88.0.5/32, 10.88.0.6/32
`
	byPub, byIP := parsePeers(conf)
	if byPub[testPub] != "10.88.0.42/32" {
		t.Fatalf("pubkey map: %v", byPub)
	}
	if byIP["10.88.0.6"] != "another" {
		t.Fatalf("ip map: %v", byIP)
	}
}

func TestContainsPrefix(t *testing.T) {
	if !containsPrefix("10.88.0.5/32, 10.88.0.42/32", "10.88.0.42/32") {
		t.Fatal("prefix not found")
	}
	if containsPrefix("10.88.0.5/32", "10.88.0.42/32") {
		t.Fatal("prefix reported present")
	}
}

func TestAddRelayUserRefusesDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth")
	if err := os.WriteFile(path, []byte("owner:pass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := addRelayUser(path, "dev-10-88-0-42-0123abcd", "0123456789abcdefghijklmn"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "dev-10-88-0-42-0123abcd:") {
		t.Fatalf("relay user missing: %s", data)
	}
	if err := addRelayUser(path, "dev-10-88-0-42-0123abcd", "anotherpassword1234567"); err == nil {
		t.Fatal("duplicate relay user accepted")
	}
}
