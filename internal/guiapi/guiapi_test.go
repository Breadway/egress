package guiapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testServer(t *testing.T, src Sources) (*Server, http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("EGRESS_STATE_DIR", dir)
	tokenPath := filepath.Join(dir, "api-token")
	srv, err := New(src, tokenPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, srv.Handler(), tokenPath
}

func baseSources() Sources {
	connected := true
	return Sources{
		Version: "1.2.3",
		Status: func() Status {
			return Status{
				Version: "1.2.3", Online: true, Connected: connected,
				Path: "direct", Exit: "Cloud relay", SpeedMbps: 12.5,
				DataGB: 1.5, UnblockedToday: 2, CircleOnline: 1,
				Network: "home",
			}
		},
		Circle: func() Circle {
			return Circle{Circle: "bread", People: []Person{
				{ID: "self", Name: "hermes", Kind: "device", Online: true, Self: true},
			}}
		},
		Protection: func() Protection {
			return Protection{Stats: ProtectionStats{Unblocked: 1, ViaCloud: 1}, Sites: []Site{
				{Domain: "example.com", Via: "cloud", Label: "Cloud relay", At: "2026-11-21T10:00:00Z"},
			}}
		},
		Retry: func(domain string) bool { return domain == "example.com" },
		SetConnected: func(on bool) error {
			connected = on
			return nil
		},
	}
}

func request(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRequiresToken(t *testing.T) {
	_, h, tokenPath := testServer(t, baseSources())
	if rec := request(t, h, http.MethodGet, "/api/v1/status", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", rec.Code)
	}
	token := strings.TrimSpace(readFile(t, tokenPath))
	if rec := request(t, h, http.MethodGet, "/api/v1/status", token, ""); rec.Code != http.StatusOK {
		t.Fatalf("valid token: got %d, want 200", rec.Code)
	}
	if rec := request(t, h, http.MethodGet, "/api/v1/status", "wrong", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", rec.Code)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestStatusReportsModeAndConnection(t *testing.T) {
	srv, h, tokenPath := testServer(t, baseSources())
	token := strings.TrimSpace(readFile(t, tokenPath))

	rec := request(t, h, http.MethodGet, "/api/v1/status", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	var got Status
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != ModeAutomatic || !got.Connected || got.SpeedMbps != 12.5 {
		t.Fatalf("unexpected status: %+v", got)
	}

	srv.sample() // establishes connected_since through the transition
	rec = request(t, h, http.MethodGet, "/api/v1/status", token, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.ConnectedSince.IsZero() {
		t.Fatal("connected_since is zero while connected")
	}
}

func TestConnectionToggle(t *testing.T) {
	_, h, tokenPath := testServer(t, baseSources())
	token := strings.TrimSpace(readFile(t, tokenPath))

	rec := request(t, h, http.MethodPost, "/api/v1/connection", token, `{"connected":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle: %d %s", rec.Code, rec.Body)
	}
	var got Status
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Connected {
		t.Fatal("still connected after pause")
	}
	if got.Path != "off" {
		t.Fatalf("path = %q, want off", got.Path)
	}

	rec = request(t, h, http.MethodPost, "/api/v1/connection", token, `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body: %d, want 400", rec.Code)
	}
}

func TestSettingsPatchIsPartialAndPersistent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EGRESS_STATE_DIR", dir)
	tokenPath := filepath.Join(dir, "api-token")
	srv, err := New(baseSources(), tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	token := strings.TrimSpace(readFile(t, tokenPath))

	rec := request(t, h, http.MethodPatch, "/api/v1/settings", token, `{"relay_fallback":false,"mode":"direct"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	var got Settings
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.RelayFallback || got.Mode != ModeDirect {
		t.Fatalf("patch not applied: %+v", got)
	}
	if got.RelayRegion != "automatic" {
		t.Fatalf("partial patch reset unrelated fields: %+v", got)
	}

	// A fresh server reads the same file back.
	again, err := New(baseSources(), tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded := again.CurrentSettings(); reloaded.RelayFallback || reloaded.Mode != ModeDirect {
		t.Fatalf("settings did not persist: %+v", reloaded)
	}
}

func TestRetryValidation(t *testing.T) {
	_, h, tokenPath := testServer(t, baseSources())
	token := strings.TrimSpace(readFile(t, tokenPath))

	if rec := request(t, h, http.MethodPost, "/api/v1/protection/retry", token, `{"domain":"example.com"}`); rec.Code != http.StatusOK {
		t.Fatalf("known site: %d %s", rec.Code, rec.Body)
	}
	if rec := request(t, h, http.MethodPost, "/api/v1/protection/retry", token, `{"domain":"nope.example"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown site: %d, want 404", rec.Code)
	}
}

func TestActivitySeedsAndDiffs(t *testing.T) {
	srv, h, tokenPath := testServer(t, baseSources())
	token := strings.TrimSpace(readFile(t, tokenPath))
	srv.sample()

	rec := request(t, h, http.MethodGet, "/api/v1/activity", token, "")
	var activity Activity
	if err := json.Unmarshal(rec.Body.Bytes(), &activity); err != nil {
		t.Fatal(err)
	}
	if len(activity.Events) == 0 {
		t.Fatal("no seeded activity")
	}

	// A new blocked site becomes an event on the next sample.
	srv.src.Protection = func() Protection {
		return Protection{Stats: ProtectionStats{Unblocked: 2}, Sites: []Site{
			{Domain: "example.com", Via: "cloud", Label: "Cloud relay", At: "2026-11-21T10:00:00Z"},
			{Domain: "new.example", Via: "cloud", Label: "Cloud relay", At: time.Now().UTC().Format(time.RFC3339)},
		}}
	}
	srv.sample()
	rec = request(t, h, http.MethodGet, "/api/v1/activity?limit=10", token, "")
	activity = Activity{}
	_ = json.Unmarshal(rec.Body.Bytes(), &activity)
	found := false
	for _, e := range activity.Events {
		if e.Title == "Unblocked new.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("new site missing from activity: %+v", activity.Events)
	}
}

func TestReportAndClear(t *testing.T) {
	src := baseSources()
	var observed string
	src.Observe = func(domain string) { observed = domain }
	_, h, tokenPath := testServer(t, src)
	token := strings.TrimSpace(readFile(t, tokenPath))

	if rec := request(t, h, http.MethodPost, "/api/v1/protection/report", token, `{"domain":"https://New.Example/path"}`); rec.Code != http.StatusOK {
		t.Fatalf("report: %d %s", rec.Code, rec.Body)
	}
	if observed != "new.example" {
		t.Fatalf("observed = %q, want new.example", observed)
	}
	for _, bad := range []string{`{"domain":""}`, `{"domain":"not a site"}`, `{"domain":"localhost"}`} {
		if rec := request(t, h, http.MethodPost, "/api/v1/protection/report", token, bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad report %s: %d, want 400", bad, rec.Code)
		}
	}

	if rec := request(t, h, http.MethodDelete, "/api/v1/activity", token, ""); rec.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
	rec := request(t, h, http.MethodGet, "/api/v1/activity", token, "")
	var activity Activity
	_ = json.Unmarshal(rec.Body.Bytes(), &activity)
	if len(activity.Events) != 0 {
		t.Fatalf("activity not cleared: %+v", activity.Events)
	}
}

func TestOptionsAndCORS(t *testing.T) {
	_, h, _ := testServer(t, baseSources())
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/settings", nil)
	req.Header.Set("Origin", "tauri://localhost")
	req.Header.Set("Access-Control-Request-Method", "PATCH")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS: %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("allow-origin = %q, want *", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
		t.Fatalf("allow-headers = %q, missing Authorization", got)
	}
}

func TestSettingsConcurrentReadWrite(t *testing.T) {
	_, h, tokenPath := testServer(t, baseSources())
	token := strings.TrimSpace(readFile(t, tokenPath))
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(2)
		value := i%2 == 0
		go func() {
			defer wg.Done()
			body := `{"relay_fallback":false}`
			if value {
				body = `{"relay_fallback":true}`
			}
			if rec := request(t, h, http.MethodPatch, "/api/v1/settings", token, body); rec.Code != http.StatusOK {
				t.Errorf("PATCH: %d %s", rec.Code, rec.Body)
			}
		}()
		go func() {
			defer wg.Done()
			if rec := request(t, h, http.MethodGet, "/api/v1/settings", token, ""); rec.Code != http.StatusOK {
				t.Errorf("GET: %d %s", rec.Code, rec.Body)
			}
		}()
	}
	wg.Wait()
}

func TestEventsStreamSendsStatus(t *testing.T) {
	_, h, tokenPath := testServer(t, baseSources())
	token := strings.TrimSpace(readFile(t, tokenPath))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := newSignalWriter()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rec, req)
		close(done)
	}()
	select {
	case <-rec.wrote:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not send status")
	}
	cancel()
	<-done
	if !strings.Contains(rec.String(), "event: status") {
		t.Fatalf("stream did not send status: %q", rec.String())
	}
}

// signalWriter is a ResponseWriter safe to read while the handler writes. The
// plain httptest recorder is not, and the SSE handler runs until the request
// context is cancelled.
type signalWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	once  sync.Once
	wrote chan struct{}
}

func newSignalWriter() *signalWriter {
	return &signalWriter{wrote: make(chan struct{})}
}

func (w *signalWriter) Header() http.Header { return http.Header{} }
func (w *signalWriter) WriteHeader(int)     {}
func (w *signalWriter) Flush()              {}
func (w *signalWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(p)
	w.once.Do(func() { close(w.wrote) })
	return n, err
}
func (w *signalWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
