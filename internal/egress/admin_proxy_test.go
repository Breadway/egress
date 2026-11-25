package egress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAdminProxyForwardsTokenAndPath(t *testing.T) {
	var gotAuth, gotPath, gotCT string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL + "/admin/api")
	proxy := newAdminProxyAt(base)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/application", strings.NewReader("id=x&action=approve"))
	req.Header.Set("X-Admin-Token", "admin-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy = %d (%s)", rec.Code, rec.Body.String())
	}
	if gotAuth != "Bearer admin-secret" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotPath != "/admin/api/application" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Fatalf("content-type = %q", gotCT)
	}
}

func TestAdminProxyRejectsMissingTokenAndUnknownPaths(t *testing.T) {
	base, _ := url.Parse("http://127.0.0.1:1/admin/api")
	proxy := newAdminProxyAt(base)

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/overview", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token = %d, want 401", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/secrets", nil)
	req.Header.Set("X-Admin-Token", "admin-secret")
	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d, want 404", rec.Code)
	}
}
