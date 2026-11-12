package health

import (
	"bytes"
	"context"
	"crypto/tls"
	"egress/internal/core"
	"egress/internal/logx"
	"egress/internal/platform"
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
	Pubkey   string  `json:"pubkey"`
	OS       string  `json:"os"`
	Arch     string  `json:"arch"`
	IP       string  `json:"ip"`
	Version  string  `json:"version"`
	Status   string  `json:"status"`          // functional, partial, or failed
	State    string  `json:"state,omitempty"` // installed, disabled
	Checks   Results `json:"checks"`
	Error    string  `json:"error,omitempty"`
	Parked   bool    `json:"parked,omitempty"`
	Diagnose string  `json:"diagnose,omitempty"`
	Log      string  `json:"log,omitempty"`
	TS       string  `json:"ts"`
}

// pendingReportPath is deliberately boring: TempDir survives long enough for
// the supervisor to flush it, and needs no new platform surface. On Windows
// the spool lives next to the log under the install directory instead:
// TempDir is per-user there, so a report spooled by the elevated installer
// would never be seen by the SYSTEM supervisor, or vice versa.
func pendingReportPath() string {
	return filepath.Join(platform.SpoolDir(), "egress-pending-report.json")
}

func collectDiagnose() string {
	var b strings.Builder
	if err := WriteDiagnose(&b); err != nil {
		fmt.Fprintf(&b, "\ndiagnose error: %v\n", err)
	}
	return logx.Truncate(b.String(), 12<<10)
}

func collectLogTail() string {
	var b strings.Builder
	logx.Tail(&b, platform.LogPath(), 40)
	return logx.Truncate(b.String(), 8<<10)
}

func BuildReport(tcfg core.TunnelConfig, results Results, verifyErr error, parked bool) ([]byte, error) {
	pub := tcfg.ReportPubkey
	if pub == "" && tcfg.PrivateKey != "" {
		if derived, err := core.PublicKey(tcfg.PrivateKey); err == nil {
			pub = derived
		}
	}
	status := results.Grade()
	// A recorded failure is a failed install even when every probe passed:
	// a later setup step failed and the install is parked, not healthy.
	if verifyErr != nil {
		status = "failed"
	}
	payload := reportPayload{
		Pubkey:  pub,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		IP:      tcfg.ClientIP,
		Version: buildVersion(),
		Status:  status,
		Parked:  parked,
		Checks:  results,
		TS:      time.Now().UTC().Format(time.RFC3339),
	}
	if verifyErr != nil {
		payload.Error = logx.Truncate(verifyErr.Error(), 2000)
	}
	// Diagnose runs last so it captures the failure state, not the setup.
	payload.Diagnose = collectDiagnose()
	payload.Log = collectLogTail()
	return json.Marshal(payload)
}

// maxSpoolAge bounds how long a spooled install report stays deliverable.
// A report spooled months ago describes a device state that no longer exists;
// delivering it as current health misdirects troubleshooting, so flush drops
// it instead of sending.
const maxSpoolAge = 7 * 24 * time.Hour

// spooledReportStale reports whether a spooled payload should be dropped
// rather than sent. The embedded TS decides when present; the file mtime is
// the fallback for payloads that predate the TS field or carry garbage.
func spooledReportStale(data []byte, modTime, now time.Time) bool {
	if len(data) == 0 {
		return true
	}
	var payload struct {
		TS string `json:"ts"`
	}
	if err := json.Unmarshal(data, &payload); err == nil && payload.TS != "" {
		if ts, err := time.Parse(time.RFC3339, payload.TS); err == nil {
			return now.Sub(ts) > maxSpoolAge
		}
	}
	if modTime.IsZero() {
		return false
	}
	return now.Sub(modTime) > maxSpoolAge
}

func SpoolReport(data []byte) {
	// The spool directory is the install directory on Windows, which may
	// not exist yet on the very first failure paths.
	_ = os.MkdirAll(platform.SpoolDir(), 0700)
	_ = os.WriteFile(pendingReportPath(), data, 0600)
}

// sendReport POSTs to the enrollment site. It tries the system path first,
// then dials the known Aegis address directly with the right SNI, so a
// poisoned local resolver cannot block the report on a filtered network.
func SendReport(data []byte) error {
	directErr := postReport(data, nil)
	if directErr == nil {
		return nil
	}
	for _, ip := range []string{core.AegisIPv4} {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 8 * time.Second}
				return d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
			},
			TLSClientConfig: &tls.Config{ServerName: core.ReportHost, MinVersion: tls.VersionTLS12},
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
		transport.TLSClientConfig = &tls.Config{ServerName: core.ReportHost, MinVersion: tls.VersionTLS12}
	}
	return postReportWith(data, transport)
}

func postReportWith(data []byte, transport *http.Transport) error {
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	resp, err := client.Post(core.ReportURL, "application/json", bytes.NewReader(data))
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
// there is nothing to send: one stat call. Spooled reports older than
// maxSpoolAge are dropped: a stale failure resurrected months later would
// arrive looking like current device health.
func FlushPendingReport() {
	path := pendingReportPath()
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if len(data) == 0 || len(data) > 128<<10 {
		_ = os.Remove(path)
		return
	}
	if spooledReportStale(data, info.ModTime(), time.Now()) {
		logx.Debugf("dropping stale spooled report")
		_ = os.Remove(path)
		return
	}
	if err := SendReport(data); err != nil {
		logx.Debugf("pending report still unsent: %v", err)
		return
	}
	_ = os.Remove(path)
	logx.Debugf("pending install report delivered")
}

// DeviceIdentity is the non-secret half of a device's tunnel identity, kept on
// disk so split installs and generic updates can identify themselves in install
// reports without holding a private key.
type DeviceIdentity struct {
	Pubkey string `json:"pubkey"`
	IP     string `json:"ip,omitempty"`
}

func DeviceIdentityPath() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\ProgramData\egress\device.json`
	case "linux":
		return "/var/lib/egress/device.json"
	default:
		if dir, err := os.UserConfigDir(); err == nil {
			return filepath.Join(dir, "egress", "device.json")
		}
		return "device.json"
	}
}

func LoadDeviceIdentity() (DeviceIdentity, error) {
	var id DeviceIdentity
	data, err := os.ReadFile(DeviceIdentityPath())
	if err != nil {
		return id, err
	}
	if err := json.Unmarshal(data, &id); err != nil {
		return id, err
	}
	return id, nil
}

func SaveDeviceIdentity(id DeviceIdentity) error {
	path := DeviceIdentityPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SendState reports a device that was disabled or enabled outside install.
// Best effort: a report must never fail the command.
func SendState(pubkey, ip, version, state, status, msg string) {
	payload := reportPayload{
		Pubkey:  pubkey,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		IP:      ip,
		Version: version,
		Status:  status,
		State:   state,
		Error:   msg,
		TS:      time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	if err := SendReport(data); err != nil {
		logx.Debugf("state report unsent: %v", err)
	}
}
