package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEffectiveStatus(t *testing.T) {
	cases := []struct {
		rep  deviceReport
		want string
	}{
		{deviceReport{Status: "functional"}, "functional"},
		{deviceReport{Status: "functional", Error: "split proxy did not start"}, "failed"},
		{deviceReport{Status: "failed"}, "failed"},
		{deviceReport{Status: "failed", Parked: true}, "parked"},
		{deviceReport{Status: "partial"}, "partial"},
		{deviceReport{}, "unknown"},
	}
	for _, c := range cases {
		if got, _ := effectiveStatus(c.rep); got != c.want {
			t.Errorf("effectiveStatus(%+v) = %q, want %q", c.rep, got, c.want)
		}
	}
}

func TestProblemText(t *testing.T) {
	if got := problemText(deviceReport{Parked: true}); got != "parked, waiting for the next release" {
		t.Errorf("parked problem: %q", got)
	}
	if got := problemText(deviceReport{Error: "first line\nsecond line"}); got != "first line" {
		t.Errorf("error problem: %q", got)
	}
	if got := problemText(deviceReport{Status: "failed"}); got != "install failed" {
		t.Errorf("failed problem: %q", got)
	}
	if got := problemText(deviceReport{Status: "functional"}); got != "" {
		t.Errorf("healthy problem: %q", got)
	}
}

func TestErrorSummary(t *testing.T) {
	long := "grant DESKTOP\\SYSTEM: exit status 1332: no mapping between account names and security IDs"
	got := errorSummary(long, 40)
	if len(got) > 43 {
		t.Errorf("summary too long: %q", got)
	}
	if got := errorSummary("one line\nmore", 80); got != "one line" {
		t.Errorf("first line: %q", got)
	}
}

// TestAdminPagesRender guards the admin views against panics and keeps the
// markup a reader depends on (status pill, device name) in place.
func TestAdminPagesRender(t *testing.T) {
	const peer = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	s := reportTestServer(t, peer)
	if w := postReport(t, s, peer); w.Code != http.StatusAccepted {
		t.Fatalf("seed report = %d", w.Code)
	}

	nonce := "0123456789abcdef0123456789abcdef"
	exp := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	cookie := base64.RawURLEncoding.EncodeToString([]byte(nonce + "|" + exp + "|" + sessionMAC(s.token, nonce, exp)))

	pages := map[string]func(http.ResponseWriter, *http.Request){
		"/admin":                    s.adminDash,
		"/admin/users":              s.adminUsers,
		"/admin/reports?user=auser": s.adminReports,
	}
	for path, h := range pages {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "auser") {
			t.Errorf("%s does not name the device", path)
		}
		if path == "/admin/reports?user=auser" && !strings.Contains(body, "functional") {
			t.Errorf("report page lost the status pill")
		}
	}
}
