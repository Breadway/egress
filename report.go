package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// reportPayload is what install sends home. The public key identifies the
// device: the server matches it against the peer recorded at publish time.
// Reports carry no secrets, only diagnostics. Sending never fails the local
// command; failures are spooled and retried later.
type reportPayload struct {
	Pubkey   string       `json:"pubkey"`
	OS       string       `json:"os"`
	Arch     string       `json:"arch"`
	IP       string       `json:"ip"`
	Version  string       `json:"version"`
	Status   string       `json:"status"` // functional, partial, or failed
	Checks   checkResults `json:"checks"`
	Error    string       `json:"error,omitempty"`
	Diagnose string       `json:"diagnose,omitempty"`
	Log      string       `json:"log,omitempty"`
	TS       string       `json:"ts"`
}

// pendingReportPath is deliberately boring: TempDir survives long enough for
// the supervisor to flush it, and needs no new platform surface.
func pendingReportPath() string {
	return filepath.Join(os.TempDir(), "egress-pending-report.json")
}

func collectDiagnose() string {
	var b strings.Builder
	if err := writeDiagnose(&b); err != nil {
		fmt.Fprintf(&b, "\ndiagnose error: %v\n", err)
	}
	return truncate(b.String(), 12<<10)
}

func collectLogTail() string {
	var b strings.Builder
	tailLog(&b, 40)
	return truncate(b.String(), 8<<10)
}

func buildReport(tcfg tunnelConfig, results checkResults, verifyErr error) ([]byte, error) {
	pub := ""
	if tcfg.PrivateKey != "" {
		if derived, err := publicKey(tcfg.PrivateKey); err == nil {
			pub = derived
		}
	}
	payload := reportPayload{
		Pubkey:  pub,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		IP:      tcfg.ClientIP,
		Version: reportVersion(),
		Status:  results.grade(),
		Checks:  results,
		TS:      time.Now().UTC().Format(time.RFC3339),
	}
	if verifyErr != nil {
		payload.Error = truncate(verifyErr.Error(), 2000)
	}
	// Diagnose runs last so it captures the failure state, not the setup.
	payload.Diagnose = collectDiagnose()
	payload.Log = collectLogTail()
	return json.Marshal(payload)
}

func spoolReport(data []byte) {
	_ = os.WriteFile(pendingReportPath(), data, 0600)
}

// sendReport POSTs to the enrollment site. It tries the system path first,
// then dials the known Aegis address directly with the right SNI, so a
// poisoned local resolver cannot block the report on a filtered network.
func sendReport(data []byte) error {
	directErr := postReport(data, nil)
	if directErr == nil {
		return nil
	}
	for _, ip := range []string{aegisIPv4} {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 8 * time.Second}
				return d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
			},
			TLSClientConfig: &tls.Config{ServerName: reportHost, MinVersion: tls.VersionTLS12},
		}
		if err := postReportWith(data, transport); err == nil {
			return nil
		}
	}
	return directErr
}

func postReport(data []byte, dial func(ctx context.Context, network, addr string) (net.Conn, error)) error {
	transport := &http.Transport{}
	if dial != nil {
		transport.DialContext = dial
		transport.TLSClientConfig = &tls.Config{ServerName: reportHost, MinVersion: tls.VersionTLS12}
	}
	return postReportWith(data, transport)
}

func postReportWith(data []byte, transport *http.Transport) error {
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	resp, err := client.Post(reportURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("report endpoint returned %s", resp.Status)
	}
	return nil
}

// flushPendingReport sends a spooled install report, if any. It is cheap when
// there is nothing to send: one stat call.
func flushPendingReport() {
	path := pendingReportPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if len(data) == 0 || len(data) > 128<<10 {
		_ = os.Remove(path)
		return
	}
	if err := sendReport(data); err != nil {
		debugf("pending report still unsent: %v", err)
		return
	}
	_ = os.Remove(path)
	debugf("pending install report delivered")
}
