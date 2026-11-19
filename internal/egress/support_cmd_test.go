package egress

import (
	"strings"
	"testing"
)

// TestRedactSupport keeps credentials out of a file people attach to a
// message. Missing a key format is a privacy bug, not a cosmetic one.
func TestRedactSupport(t *testing.T) {
	in := strings.Join([]string{
		"PrivateKey = 8Fh3kLm2Qp9Zr4Ts6Vw8Xy0Ab2Cd4Ef6Gh8Ij0Kl2Mn=",
		"password: hunter2-hunter2-hunter2",
		"token=abc123def456",
		"just a normal line about routes",
		"a bare key 8Fh3kLm2Qp9Zr4Ts6Vw8Xy0Ab2Cd4Ef6Gh8Ij0Kl2Mn=",
	}, "\n")

	out := redactSupport(in)
	for _, secret := range []string{"hunter2", "abc123def456", "8Fh3kLm2Qp9Zr4Ts6Vw8Xy0Ab2Cd4Ef6Gh8Ij0Kl2Mn"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q survived redaction:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "just a normal line about routes") {
		t.Errorf("redaction ate an ordinary line:\n%s", out)
	}
}
