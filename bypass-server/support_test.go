package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestSupportUploadStoresForEnrolledDevice covers the optional upload: a bound
// device may post a bundle, a stranger may not, and something that is not a zip
// is refused.
func TestSupportUploadStoresForEnrolledDevice(t *testing.T) {
	const key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	s := reportTestServer(t)
	if err := saveDevices(s.devicesPath(), deviceRegistry{
		Version: 1,
		Devices: []device{{ID: "d-11111111", Label: "vm", TokenHash: "x", Status: "bound", Created: "t", PubKey: key}},
	}); err != nil {
		t.Fatal(err)
	}

	body := append([]byte{'P', 'K', 3, 4}, []byte("bundle")...)
	req := httptest.NewRequest(http.MethodPost, "/api/support", bytes.NewReader(body))
	req.Header.Set("X-Egress-Pubkey", key)
	req.Header.Set("X-Egress-Version", "0.4.47")
	rec := httptest.NewRecorder()
	s.apiSupport(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}

	file, meta, ok := s.latestSupport(key)
	if !ok {
		t.Fatal("bundle was not stored")
	}
	if meta.Bytes != len(body) {
		t.Errorf("meta bytes = %d, want %d", meta.Bytes, len(body))
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("stored file missing: %v", err)
	}

	stranger := httptest.NewRequest(http.MethodPost, "/api/support", bytes.NewReader(body))
	stranger.Header.Set("X-Egress-Pubkey", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=")
	rec = httptest.NewRecorder()
	s.apiSupport(rec, stranger)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown device = %d, want 404", rec.Code)
	}

	notZip := httptest.NewRequest(http.MethodPost, "/api/support", bytes.NewReader([]byte("hello")))
	notZip.Header.Set("X-Egress-Pubkey", key)
	rec = httptest.NewRecorder()
	s.apiSupport(rec, notZip)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("non-zip = %d, want 400", rec.Code)
	}
}
