package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Device install reports. The client POSTs one at the end of every install
// (and retries a spooled one later); the admin UI shows the latest per peer.
//
// Reports are diagnostic data, not an authenticated channel: the public key
// identifies the device, and anyone can claim any key. The admin matches them
// against enrolled peers and treats them as a hint, not proof.
type deviceReport struct {
	Pubkey   string            `json:"pubkey"`
	OS       string            `json:"os"`
	Arch     string            `json:"arch"`
	IP       string            `json:"ip"`
	Version  string            `json:"version"`
	Status   string            `json:"status"`
	Checks   map[string]string `json:"checks"`
	Error    string            `json:"error"`
	Parked   bool              `json:"parked,omitempty"`
	Diagnose string            `json:"diagnose"`
	Log      string            `json:"log"`
	TS       string            `json:"ts"`
}

type storedReport struct {
	Received string       `json:"received"`
	Report   deviceReport `json:"report"`
}

const (
	reportBodyMax    = 128 << 10
	reportRateMax    = 20
	reportRateWindow = time.Hour
	// maxStoredReports caps the reports directory; pruneReports deletes the
	// oldest first. Enrolled devices number in the tens.
	maxStoredReports = 512
)

// reportSlug maps a public key to a filename without touching the disk with
// base64 padding or slashes.
func reportSlug(pubkey string) string {
	r := strings.NewReplacer("+", "-", "/", "_")
	return strings.TrimRight(r.Replace(pubkey), "=")
}

func (s *server) apiReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allow(s.reports, clientIP(r), reportRateMax, reportRateWindow) {
		http.Error(w, "too many reports; try again later", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, reportBodyMax)
	var rep deviceReport
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	if !validWireGuardKey(rep.Pubkey) {
		http.Error(w, "bad pubkey", http.StatusBadRequest)
		return
	}
	switch rep.Status {
	case "functional", "partial", "failed":
	default:
		http.Error(w, "bad status", http.StatusBadRequest)
		return
	}
	rep.OS = truncateText(rep.OS, 16)
	rep.Arch = truncateText(rep.Arch, 16)
	rep.IP = truncateText(rep.IP, 64)
	rep.Version = truncateText(rep.Version, 32)
	rep.Error = truncateText(rep.Error, 2048)
	rep.Diagnose = truncateText(rep.Diagnose, 16<<10)
	rep.Log = truncateText(rep.Log, 16<<10)
	rep.TS = truncateText(rep.TS, 64)
	if rep.Checks == nil {
		rep.Checks = map[string]string{}
	}
	clean := map[string]string{}
	for k, v := range rep.Checks {
		if len(clean) >= 16 {
			break
		}
		clean[truncateText(k, 32)] = truncateText(v, 512)
	}
	rep.Checks = clean

	// Reports are accepted only for enrolled peers: anyone can mint a
	// well-shaped key, and without this gate an anonymous client can
	// overwrite any device's health or fill the disk with fresh keys.
	if !s.peerEnrolled(rep.Pubkey) {
		http.Error(w, "unknown device", http.StatusNotFound)
		return
	}

	dir := filepath.Join(s.state, "reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	stored := storedReport{
		Received: time.Now().UTC().Format(time.RFC3339),
		Report:   rep,
	}
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	tmp := filepath.Join(dir, reportSlug(rep.Pubkey)+".json.new")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, reportSlug(rep.Pubkey)+".json")); err != nil {
		_ = os.Remove(tmp)
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	pruneReports(dir, maxStoredReports)
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintln(w, "recorded")
}

// peerEnrolled reports whether pubkey belongs to a download login, i.e. a
// device this server actually enrolled.
func (s *server) peerEnrolled(pubkey string) bool {
	if pubkey == "" {
		return false
	}
	for _, u := range s.loadUsers() {
		if u.Peer == pubkey {
			return true
		}
	}
	return false
}

// pruneReports caps the stored reports at keep files, deleting the oldest
// first, so the directory cannot grow without bound.
func pruneReports(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= keep {
		return
	}
	type aged struct {
		name string
		mod  time.Time
	}
	var files []aged
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, aged{e.Name(), info.ModTime()})
	}
	if len(files) <= keep {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	for _, f := range files[:len(files)-keep] {
		_ = os.Remove(filepath.Join(dir, f.name))
	}
}

func (s *server) loadReport(pubkey string) (*storedReport, bool) {
	if pubkey == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(s.state, "reports", reportSlug(pubkey)+".json"))
	if err != nil {
		return nil, false
	}
	var stored storedReport
	if json.Unmarshal(data, &stored) != nil {
		return nil, false
	}
	return &stored, true
}

// reportPill renders the device status for the logins table.
func reportPill(stored *storedReport) string {
	if stored == nil {
		return `<span class="pill">unknown</span>`
	}
	switch stored.Report.Status {
	case "functional":
		return fmt.Sprintf(`<span class="pill ok">functional</span><br><span class="muted">%s</span>`,
			esc(timeAgo(stored.Received)))
	case "partial":
		return fmt.Sprintf(`<span class="pill new">partial</span><br><span class="muted">%s</span>`,
			esc(timeAgo(stored.Received)))
	default:
		return fmt.Sprintf(`<span class="pill new">failed</span><br><span class="muted">%s</span>`,
			esc(timeAgo(stored.Received)))
	}
}

func timeAgo(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// adminReports shows one device's latest install report: checks, error,
// diagnose output and log tail.
func (s *server) adminReports(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.URL.Query().Get("user")
	users := s.loadUsers()
	u, ok := users[username]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	stored, found := s.loadReport(u.Peer)

	var b strings.Builder
	fmt.Fprintf(&b, `<div class="admin-head"><h1>%s</h1></div>`, esc(username))
	b.WriteString(adminSubnav("users"))
	if !found {
		b.WriteString(`<div class="table-wrap"><div class="empty"><strong>No reports yet.</strong>
This device has not reported an install. Older binaries predate reporting.</div></div>`)
		s.renderNav(w, true, "admin", "Device report", b.String())
		return
	}
	rep := stored.Report
	deviceTime := esc(displayTime(rep.TS))
	if rep.TS == "" {
		deviceTime = "unknown device time"
	}
	fmt.Fprintf(&b, `<div class="card tight"><p style="margin:0">Status: %s<br>
<span class="muted">Reported %s &middot; device time %s &middot; %s/%s &middot; build %s &middot; tunnel %s</span></p></div>`,
		reportPill(stored), esc(displayTime(stored.Received)), deviceTime,
		esc(rep.OS), esc(rep.Arch), esc(rep.Version), esc(rep.IP))

	var names []string
	for k := range rep.Checks {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) > 0 {
		b.WriteString(`<div class="table-wrap"><table><thead><tr><th>Check</th><th>Result</th></tr></thead><tbody>`)
		for _, k := range names {
			v := rep.Checks[k]
			cell := `<span class="pill ok">ok</span>`
			switch v {
			case "", "up", "ok", "skipped":
			default:
				cell = fmt.Sprintf(`<code>%s</code>`, esc(v))
			}
			fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%s</td></tr>`, esc(k), cell)
		}
		b.WriteString(`</tbody></table></div>`)
	}
	if rep.Error != "" {
		fmt.Fprintf(&b, `<div class="card"><h2>Error</h2><pre>%s</pre></div>`, esc(rep.Error))
	}
	if rep.Diagnose != "" {
		fmt.Fprintf(&b, `<div class="card"><h2>Diagnose</h2><pre>%s</pre></div>`, esc(rep.Diagnose))
	}
	if rep.Log != "" {
		fmt.Fprintf(&b, `<div class="card"><h2>Log tail</h2><pre>%s</pre></div>`, esc(rep.Log))
	}
	s.renderNav(w, true, "admin", "Device report", b.String())
}
