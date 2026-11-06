package main

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func sessionRequest(t *testing.T, s *server, cookie *http.Cookie) *http.Request {
	t.Helper()
	r, _ := http.NewRequest("GET", "/admin", nil)
	r.AddCookie(cookie)
	return r
}

// oldSessionValue mints a pre-rotation exp|sig cookie for compat tests.
func oldSessionValue(s *server) string {
	exp := "9999999999"
	return base64.RawURLEncoding.EncodeToString([]byte(exp + "|" + sessionMAC(s.token, "", exp)))
}

func csrfPost(t *testing.T, s *server, cookie *http.Cookie, token string) *http.Request {
	t.Helper()
	form := url.Values{"csrf": {token}}
	r, _ := http.NewRequest("POST", "/admin", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSessionCSRFIsPerSession(t *testing.T) {
	s := &server{token: "test-token-1234567890"}
	c1 := s.mintSession()
	c2 := s.mintSession()
	if c1 == nil || c2 == nil {
		t.Fatal("mintSession returned nil")
	}
	if c1.Value == c2.Value {
		t.Fatal("two logins share a session cookie; CSRF namespaces are not isolated")
	}
	r1 := sessionRequest(t, s, c1)
	r2 := sessionRequest(t, s, c2)
	if !s.validSession(r1) || !s.validSession(r2) {
		t.Fatal("fresh sessions must validate")
	}
	tok1 := s.csrfToken(r1)
	tok2 := s.csrfToken(r2)
	if tok1 == tok2 {
		t.Error("CSRF tokens must differ across sessions")
	}
	if !s.checkCSRF(csrfPost(t, s, c1, tok1)) {
		t.Error("own-session CSRF token must verify")
	}
	if s.checkCSRF(csrfPost(t, s, c2, tok1)) {
		t.Error("session A's token must not verify with session B")
	}
	if s.checkCSRF(csrfPost(t, s, c1, tok2)) {
		t.Error("session B's token must not verify with session A")
	}
}

func TestOldSessionFormatStillValidates(t *testing.T) {
	s := &server{token: "test-token-1234567890"}
	// Pre-rotation exp|sig cookie must keep working until it expires.
	c := &http.Cookie{Name: sessionCookie, Value: oldSessionValue(s)}
	r := sessionRequest(t, s, c)
	if !s.validSession(r) {
		t.Fatal("old-format session must still validate")
	}
	tok := s.csrfToken(r)
	if !s.checkCSRF(csrfPost(t, s, c, tok)) {
		t.Error("old-format session CSRF must verify with its own token")
	}
}
