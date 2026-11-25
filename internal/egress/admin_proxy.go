package egress

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"egress/internal/core"
)

// adminProxy forwards the desktop admin app's requests to the bypass server
// through the authenticated Aegis tunnel. The admin token is supplied per
// request by the app and is never stored by the daemon.
//
// Only these endpoints are forwarded:
//
//	GET  overview, applications, devices
//	POST application, device
type adminProxy struct {
	base   *url.URL
	client *http.Client
}

func newAdminProxy() http.Handler {
	base, _ := url.Parse("https://bypass.breadway.dev/admin/api")
	return newAdminProxyAt(base)
}

func newAdminProxyAt(base *url.URL) *adminProxy {
	return &adminProxy{
		base: base,
		client: &http.Client{
			Timeout: 25 * time.Second,
			Transport: &http.Transport{
				DialContext: core.ControlDialContext,
			},
		},
	}
}

func (p *adminProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.Header.Get("X-Admin-Token"))
	if token == "" {
		writeProxyError(w, http.StatusUnauthorized, "an admin token is required")
		return
	}

	endpoint := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/")
	if endpoint == r.URL.Path || endpoint == "" {
		writeProxyError(w, http.StatusNotFound, "unknown admin endpoint")
		return
	}
	allowed := false
	switch endpoint {
	case "overview", "applications", "devices":
		allowed = r.Method == http.MethodGet
	case "application", "device":
		allowed = r.Method == http.MethodPost
	}
	if !allowed {
		writeProxyError(w, http.StatusNotFound, "unknown admin endpoint")
		return
	}

	target := *p.base
	target.Path = strings.TrimRight(p.base.Path, "/") + "/" + endpoint
	target.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		writeProxyError(w, http.StatusBadRequest, "could not build the request")
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, "the admin service did not answer")
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 4<<20))
}

func writeProxyError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":{"code":"admin","message":"`+message+`"}}`)
}
