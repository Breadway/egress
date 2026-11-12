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
// effectiveStatus folds the stored status, the error text and the parked flag
// into the state a reader cares about. Older builds graded only their probes,
// so a report can say functional while carrying a setup error.
func effectiveStatus(rep deviceReport) (label, class string) {
	switch {
	case rep.Parked:
		return "parked", "new"
	case rep.Status == "failed" || rep.Error != "":
		return "failed", "bad"
	case rep.Status == "partial":
		return "partial", "new"
	case rep.Status == "":
		return "unknown", ""
	default:
		return rep.Status, "ok"
	}
}

// errorSummary returns the first line of an error, shortened for a table cell.
func errorSummary(msg string, limit int) string {
	line := strings.TrimSpace(strings.SplitN(msg, "\n", 2)[0])
	if len(line) <= limit {
		return line
	}
	return strings.TrimSpace(line[:limit]) + "..."
}

func reportPill(stored *storedReport) string {
	if stored == nil {
		return `<span class="pill">no report</span>`
	}
	label, class := effectiveStatus(stored.Report)
	return fmt.Sprintf(`<span class="pill %s">%s</span><span class="cell-sub">%s</span>`,
		class, esc(label), esc(timeAgo(stored.Received)))
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

// adminReports shows one device's latest install report. The reader wants the
// verdict and the reason first, so the order is status, reason, checks, then
// the long output folded away.
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
	label, class := effectiveStatus(rep)
	deviceTime := esc(displayTime(rep.TS))
	if rep.TS == "" {
		deviceTime = "unknown device time"
	}

	b.WriteString(`<div class="card tight"><div class="report-head">`)
	fmt.Fprintf(&b, `<span class="pill %s">%s</span>`, class, esc(label))
	if rep.Version != "" {
		fmt.Fprintf(&b, `<span class="report-meta">build <strong>%s</strong></span>`, esc(rep.Version))
	}
	fmt.Fprintf(&b, `<span class="report-meta">%s/%s</span>`, esc(rep.OS), esc(rep.Arch))
	if rep.IP != "" {
		fmt.Fprintf(&b, `<span class="report-meta">%s</span>`, esc(rep.IP))
	}
	fmt.Fprintf(&b, `<span class="report-meta">reported %s</span>`, esc(displayTime(stored.Received)))
	b.WriteString(`</div>`)
	fmt.Fprintf(&b, `<p class="muted" style="margin:.5rem 0 0">Device time %s</p></div>`, deviceTime)

	switch {
	case rep.Parked:
		b.WriteString(`<div class="alert info"><strong>Parked, waiting for a fix.</strong>
Networking was left working. The install stays on disk and checks for a new release every minute, so the next publish lands on its own.</div>`)
	case rep.Error != "":
		fmt.Fprintf(&b, `<div class="alert error"><strong>%s</strong></div>`, esc(errorSummary(rep.Error, 240)))
	case label == "failed":
		b.WriteString(`<div class="alert error"><strong>Install failed, with no error text reported.</strong></div>`)
	}

	var names []string
	for k := range rep.Checks {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) > 0 {
		b.WriteString(`<div class="table-wrap compact"><table><thead><tr><th>Check</th><th>Result</th></tr></thead><tbody>`)
		for _, k := range names {
			v := rep.Checks[k]
			var cell string
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "ok", "up":
				cell = `<span class="pill ok">ok</span>`
			case "skipped":
				cell = `<span class="pill skip">skipped</span>`
			case "":
				cell = `<span class="muted">not reported</span>`
			case "down", "failed":
				cell = `<span class="pill bad">failed</span>`
			default:
				cell = `<span class="pill bad">failed</span><span class="cell-sub">` + esc(v) + `</span>`
			}
			fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%s</td></tr>`, esc(k), cell)
		}
		b.WriteString(`</tbody></table></div>`)
	}

	if rep.Error != "" {
		fmt.Fprintf(&b, `<div class="card"><h2>Error</h2><pre class="err">%s</pre></div>`, esc(rep.Error))
	}
	if rep.Diagnose != "" {
		fmt.Fprintf(&b, `<details class="card"><summary>Diagnose output</summary><pre>%s</pre></details>`, esc(rep.Diagnose))
	}
	if rep.Log != "" {
		fmt.Fprintf(&b, `<details class="card"><summary>Log tail</summary><pre>%s</pre></details>`, esc(rep.Log))
	}
	s.renderNav(w, true, "admin", "Device report", b.String())
}

// deviceRow is one login joined with its latest report, ordered so the devices
// that need attention come first.
type deviceRow struct {
	Name   string
	User   user
	Stored *storedReport
	Label  string
	Class  string
}

var deviceRank = map[string]int{
	"failed": 0, "parked": 1, "partial": 2, "no report": 3, "unknown": 4, "functional": 5,
}

func (s *server) deviceRows() []deviceRow {
	users := s.loadUsers()
	rows := make([]deviceRow, 0, len(users))
	for name, u := range users {
		row := deviceRow{Name: name, User: u, Label: "no report"}
		if stored, ok := s.loadReport(u.Peer); ok {
			row.Stored = stored
			row.Label, row.Class = effectiveStatus(stored.Report)
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		ri, rj := deviceRank[rows[i].Label], deviceRank[rows[j].Label]
		if ri != rj {
			return ri < rj
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

// problemText is the one line a reader needs next to a device's status.
func problemText(rep deviceReport) string {
	switch {
	case rep.Parked:
		return "parked, waiting for the next release"
	case rep.Error != "":
		return errorSummary(rep.Error, 90)
	case rep.Status == "failed":
		return "install failed"
	case rep.Status == "partial":
		return "some checks failed"
	}
	return ""
}

// deviceTable is the compact device list shared by the dashboard and Logins.
func deviceTable(rows []deviceRow) string {
	var b strings.Builder
	b.WriteString(`<div class="table-wrap compact"><table><thead><tr><th>Login</th><th>Status</th><th>Build</th><th>Last report</th><th>Problem</th></tr></thead><tbody>`)
	for _, row := range rows {
		build := `<span class="muted">-</span>`
		when := `<span class="muted">never</span>`
		problem := "no install report yet"
		if row.Stored != nil {
			if row.Stored.Report.Version != "" {
				build = esc(row.Stored.Report.Version)
			}
			when = esc(timeAgo(row.Stored.Received))
			problem = problemText(row.Stored.Report)
		}
		fmt.Fprintf(&b, `<tr><td><a href="/admin/reports?user=%s"><code>%s</code></a></td><td>%s</td><td>%s</td><td class="muted">%s</td><td class="problem">%s</td></tr>`,
			esc(row.Name), esc(row.Name), reportPill(row.Stored), build, when, esc(problem))
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}
