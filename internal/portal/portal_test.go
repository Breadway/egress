package portal

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func renderBody(t *testing.T, snap Snapshot) string {
	t.Helper()
	rec := httptest.NewRecorder()
	newHandler(func() Snapshot { return snap }).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	return rec.Body.String()
}

func TestPortalShowsHowEachSiteIsReached(t *testing.T) {
	now := time.Now()
	body := renderBody(t, Snapshot{
		Network:   "unknown|192.168.1.1",
		Online:    true,
		Generated: now,
		Domains: []Domain{
			{Name: "reddit.com", ServedBy: "hestia", Evidence: "tls-stall", LastProbe: now},
			{Name: "other.example", Unserved: true, Evidence: "tls-stall", LastProbe: now},
			{Name: "direct.example", Evidence: "tls-stall", LastProbe: now},
		},
	})
	for _, want := range []string{
		"via hestia",
		"direct",
		"cloud exit",
		"every exit refused it",
		"cannot be routed through any available exit",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	if strings.Contains(body, "egress is offline") {
		t.Error("online snapshot claims the tunnel is down")
	}
}

func TestPortalOfflineBanner(t *testing.T) {
	body := renderBody(t, Snapshot{Online: false, Domains: []Domain{
		{Name: "other.example", Unserved: true, Evidence: "tls-stall"},
	}})
	if !strings.Contains(body, "egress is offline") {
		t.Error("offline snapshot has no offline banner")
	}
	if !strings.Contains(body, "until the tunnel is back") {
		t.Error("offline snapshot does not explain the direct-only state")
	}
}

func TestPortalPutsUnservedFirst(t *testing.T) {
	body := renderBody(t, Snapshot{Domains: []Domain{
		{Name: "aaa.example", ServedBy: "hestia"},
		{Name: "zzz.example", Unserved: true},
	}})
	if strings.Index(body, "zzz.example") > strings.Index(body, "aaa.example") {
		t.Error("unserved site is not listed first")
	}
}

func TestPortalOnlyServesRoot(t *testing.T) {
	rec := httptest.NewRecorder()
	newHandler(func() Snapshot { return Snapshot{} }).ServeHTTP(rec, httptest.NewRequest("GET", "/etc/passwd", nil))
	if rec.Code != 404 {
		t.Fatalf("status %d, want 404", rec.Code)
	}
}

func TestPortalEscapesNames(t *testing.T) {
	body := renderBody(t, Snapshot{Domains: []Domain{
		{Name: `<script>alert(1)</script>.example`, Unserved: true},
	}})
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("domain name was not escaped")
	}
}
