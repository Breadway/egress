package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// First-activation enrollment.
//
// An invite carries a single-use token. On first run the device generates its
// own keypair, sends only the public key, and receives an address and a relay
// credential. The private key never leaves the device. A bound invite cannot
// be used again, so a shared installer stops being a working identity.
//
// Existing embedded-key builds are untouched: this path only ever appends a
// new peer and a new relay user.

const (
	enrollTokenBytes = 32
	enrollValidHours = 72
	enrollIPFirst    = 20
	enrollIPLast     = 199
	enrollWait       = 6 * time.Second
	enrollBodyMax    = 4 << 10
)

type device struct {
	ID        string `json:"id"`
	Label     string `json:"label,omitempty"`
	TokenHash string `json:"token_hash"`
	Status    string `json:"status"` // issued or bound
	Created   string `json:"created"`
	Expires   string `json:"expires,omitempty"`
	PubKey    string `json:"pubkey,omitempty"`
	IP        string `json:"ip,omitempty"`
	RelayUser string `json:"relay_user,omitempty"`
	BoundAt   string `json:"bound_at,omitempty"`
	Platform  string `json:"platform,omitempty"`
	Arch      string `json:"arch,omitempty"`
	// Circle is the relationship group a device belongs to. Peers are only
	// visible inside a circle; an empty value is the original "bread" circle,
	// so existing devices keep working unchanged.
	Circle string `json:"circle,omitempty"`
	// DerpPubKey is the device's relay identity. It is separate from the
	// WireGuard key on purpose: the relay learns this key, and it must not be
	// the key that protects the tunnel.
	DerpPubKey string `json:"derp_pubkey,omitempty"`
}

type deviceRegistry struct {
	Version int      `json:"version"`
	Devices []device `json:"devices"`
}

var (
	enrollIDRe     = regexp.MustCompile(`^d-[0-9a-f]{8}$`)
	enrollRelayRe  = regexp.MustCompile(`^dev-10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}-[0-9a-f]{8}$`)
	enrollPubKeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)

func (s *server) devicesPath() string {
	if p := os.Getenv("BYPASS_DEVICES"); p != "" {
		return p
	}
	return filepath.Join(s.state, "devices.json")
}

func (s *server) enrollDir() string { return filepath.Join(s.state, "enroll") }

func loadDevices(path string) (deviceRegistry, error) {
	reg := deviceRegistry{Version: 1}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return reg, nil
		}
		return reg, err
	}
	if err := json.Unmarshal(data, &reg); err != nil {
		return reg, err
	}
	return reg, nil
}

func saveDevices(path string, reg deviceRegistry) error {
	reg.Version = 1
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newToken() (string, error) {
	raw := make([]byte, enrollTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// freeAddresses lists the unbound addresses in the enrollment pool.
func freeAddresses(reg deviceRegistry) []string {
	used := map[string]bool{}
	for _, d := range reg.Devices {
		if d.IP != "" {
			used[d.IP] = true
		}
	}
	var out []string
	for last := enrollIPFirst; last <= enrollIPLast; last++ {
		ip := fmt.Sprintf("10.88.0.%d", last)
		if !used[ip] {
			out = append(out, ip)
		}
	}
	return out
}

func fingerprint(pub string) string {
	raw, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return pub
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func validExpiry(expires string) bool {
	if expires == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, expires)
	return err == nil && time.Now().Before(t)
}

// enrollClaim is the request the server leaves for the root agent.
type enrollClaim struct {
	ID        string `json:"id"`
	PubKey    string `json:"pubkey"`
	IP        string `json:"ip"`
	RelayUser string `json:"relay_user"`
	RelayPass string `json:"relay_pass"`
	Label     string `json:"label,omitempty"`
}

type enrollResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (s *server) apiEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allow(s.enrolls, clientIP(r), 12, time.Hour) {
		http.Error(w, "too many enrollments; try again later", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, enrollBodyMax)
	var req struct {
		Token    string `json:"token"`
		PubKey   string `json:"pubkey"`
		Platform string `json:"platform"`
		Arch     string `json:"arch"`
		Label    string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "unreadable request", http.StatusBadRequest)
		return
	}
	req.PubKey = strings.TrimSpace(req.PubKey)
	if !enrollPubKeyRe.MatchString(req.PubKey) {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}
	if len(req.Token) < 20 || len(req.Token) > 128 {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if len(req.Platform) > 16 || len(req.Arch) > 16 || len(req.Label) > 64 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	s.devicesMu.Lock()
	defer s.devicesMu.Unlock()
	reg, err := loadDevices(s.devicesPath())
	if err != nil {
		http.Error(w, "device registry unreadable", http.StatusInternalServerError)
		return
	}
	hash := hashToken(req.Token)
	index := -1
	for i, d := range reg.Devices {
		if d.TokenHash == hash {
			index = i
			break
		}
	}
	if index < 0 {
		http.Error(w, "invalid or already used token", http.StatusUnauthorized)
		return
	}
	d := reg.Devices[index]
	if d.Status != "issued" {
		http.Error(w, "token already used", http.StatusUnauthorized)
		return
	}
	if !validExpiry(d.Expires) {
		http.Error(w, "token expired", http.StatusUnauthorized)
		return
	}

	if err := os.MkdirAll(s.enrollDir(), 0770); err != nil {
		http.Error(w, "enrollment unavailable", http.StatusServiceUnavailable)
		return
	}
	free := freeAddresses(reg)
	if len(free) == 0 {
		http.Error(w, "no address available", http.StatusServiceUnavailable)
		return
	}
	// The agent is the only party that sees peers created from embedded-key
	// builds, so a collision surfaces as "in use" and the next address is tried.
	for attempt := 0; attempt < 4 && attempt < len(free); attempt++ {
		ip := free[attempt]
		suffix := make([]byte, 4)
		_, _ = rand.Read(suffix)
		relayUser := "dev-" + strings.ReplaceAll(ip, ".", "-") + "-" + hex.EncodeToString(suffix)
		pass, err := newToken()
		if err != nil {
			http.Error(w, "enrollment failed", http.StatusInternalServerError)
			return
		}
		claim := enrollClaim{ID: d.ID, PubKey: req.PubKey, IP: ip, RelayUser: relayUser, RelayPass: pass, Label: d.Label}
		result, err := s.runEnrollClaim(claim)
		if err != nil {
			http.Error(w, "enrollment service: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		if !result.OK {
			if strings.Contains(result.Error, "in use") {
				continue
			}
			http.Error(w, "enrollment failed: "+result.Error, http.StatusServiceUnavailable)
			return
		}
		reg.Devices[index].Status = "bound"
		reg.Devices[index].PubKey = req.PubKey
		reg.Devices[index].IP = ip
		reg.Devices[index].RelayUser = relayUser
		reg.Devices[index].BoundAt = time.Now().UTC().Format(time.RFC3339)
		reg.Devices[index].Platform = req.Platform
		reg.Devices[index].Arch = req.Arch
		sort.Slice(reg.Devices, func(i, j int) bool { return reg.Devices[i].Created > reg.Devices[j].Created })
		if err := saveDevices(s.devicesPath(), reg); err != nil {
			http.Error(w, "could not record the device", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{
			"device":      d.ID,
			"ip":          ip,
			"relay_user":  relayUser,
			"relay_pass":  pass,
			"fingerprint": fingerprint(req.PubKey),
		})
		return
	}
	http.Error(w, "no free address", http.StatusServiceUnavailable)
}

// runEnrollClaim hands one binding to the root agent and waits for its answer.
func (s *server) runEnrollClaim(claim enrollClaim) (enrollResult, error) {
	var res enrollResult
	if !enrollIDRe.MatchString(claim.ID) {
		return res, fmt.Errorf("bad device id")
	}
	reqPath := filepath.Join(s.enrollDir(), claim.ID+".json")
	resPath := filepath.Join(s.enrollDir(), claim.ID+".result")
	_ = os.Remove(resPath)
	data, err := json.Marshal(claim)
	if err != nil {
		return res, err
	}
	if err := os.WriteFile(reqPath, data, 0600); err != nil {
		return res, err
	}
	deadline := time.Now().Add(enrollWait)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(resPath)
		if err == nil {
			_ = os.Remove(resPath)
			_ = os.Remove(reqPath)
			if json.Unmarshal(data, &res) != nil {
				return res, fmt.Errorf("unreadable enrollment result")
			}
			return res, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = os.Remove(reqPath)
	return res, fmt.Errorf("timed out; is egress-enroll-agent running?")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// adminDevices lists invites and bound devices. It never removes a bound
// device: revocation of an active identity is a deliberate manual act.
func (s *server) adminDevices(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.devicesMu.Lock()
	reg, loadErr := loadDevices(s.devicesPath())
	s.devicesMu.Unlock()

	created := ""
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		switch r.FormValue("action") {
		case "invite":
			token, err := newToken()
			if err != nil {
				http.Error(w, "could not create a token", http.StatusInternalServerError)
				return
			}
			idRaw := make([]byte, 4)
			_, _ = rand.Read(idRaw)
			label := strings.TrimSpace(r.FormValue("label"))
			if label == "" {
				label = "unlabelled"
			}
			s.devicesMu.Lock()
			reg.Devices = append(reg.Devices, device{
				ID:        "d-" + hex.EncodeToString(idRaw),
				Label:     label,
				TokenHash: hashToken(token),
				Status:    "issued",
				Created:   time.Now().UTC().Format(time.RFC3339),
				Expires:   time.Now().Add(enrollValidHours * time.Hour).UTC().Format(time.RFC3339),
			})
			sort.Slice(reg.Devices, func(i, j int) bool { return reg.Devices[i].Created > reg.Devices[j].Created })
			err = saveDevices(s.devicesPath(), reg)
			s.devicesMu.Unlock()
			if err != nil {
				http.Error(w, "could not save the invite", http.StatusInternalServerError)
				return
			}
			created = token
		case "circle":
			id := r.FormValue("id")
			circle := normalizeCircle(r.FormValue("circle"))
			s.devicesMu.Lock()
			changed := false
			for i := range reg.Devices {
				if reg.Devices[i].ID == id {
					reg.Devices[i].Circle = circle
					changed = true
					break
				}
			}
			if changed {
				_ = saveDevices(s.devicesPath(), reg)
			}
			s.devicesMu.Unlock()
		case "revoke":
			id := r.FormValue("id")
			s.devicesMu.Lock()
			kept := reg.Devices[:0]
			removed := false
			for _, d := range reg.Devices {
				if d.ID == id && d.Status == "issued" {
					removed = true
					continue
				}
				kept = append(kept, d)
			}
			if removed {
				reg.Devices = kept
				_ = saveDevices(s.devicesPath(), reg)
			}
			s.devicesMu.Unlock()
		}
		reg, loadErr = loadDevices(s.devicesPath())
	}

	var b strings.Builder
	b.WriteString(`<div class="admin-head"><h1>Devices</h1></div>`)
	b.WriteString(adminSubnav("devices"))
	b.WriteString(`<p>One-time invites. The device brings its own key.</p>`)
	if created != "" {
		fmt.Fprintf(&b, `<div class="banner ok"><strong>New invite token</strong> (shown once):<pre>%s</pre>Send it with the installer. The other side runs:<pre>egress install --enroll-token &lt;token&gt;</pre>or puts the token in <code>enroll.txt</code> next to the exe and runs it as administrator.</div>`, template.HTMLEscapeString(created))
	}
	if loadErr != nil {
		fmt.Fprintf(&b, `<p class="warn">Could not read devices.json: %s</p>`, template.HTMLEscapeString(loadErr.Error()))
	}
	b.WriteString(`<form method="post" action="/admin/devices" class="card tight"><input type="hidden" name="action" value="invite"><label for="invite-label">Label</label><input id="invite-label" name="label" placeholder="Ethan"><div class="actions"><button class="btn" type="submit">Create invite</button></div></form>`)
	if len(reg.Devices) == 0 {
		b.WriteString(`<p class="muted">No invites yet.</p>`)
	} else {
		b.WriteString(`<div class="table-wrap"><table><thead><tr><th>Device</th><th>Circle</th><th>State</th><th>Build</th><th>Last report</th><th>Update check</th><th>Address</th><th></th></tr></thead><tbody>`)
		fl := s.loadFleet()
		for _, d := range reg.Devices {
			appCell := ""
			if a, ok := fl.deviceApp(d); ok {
				appCell = ` &middot; <a href="/admin/applications/` + template.HTMLEscapeString(a.ID) + `">` + template.HTMLEscapeString(a.Name) + `</a>`
			}
			deviceCell := fmt.Sprintf(`<a href="/admin/devices/%s"><strong>%s</strong></a><span class="cell-sub"><code>%s</code>%s</span>`,
				template.HTMLEscapeString(d.ID), template.HTMLEscapeString(d.Label), template.HTMLEscapeString(d.ID), appCell)

			state, class, build, reportCell, pollCell := s.deviceState(d)
			if build == "" {
				build = "&mdash;"
			}
			action := ""
			if d.Status == "issued" {
				action = `<form method="post" action="/admin/devices"><input type="hidden" name="action" value="revoke"><input type="hidden" name="id" value="` + template.HTMLEscapeString(d.ID) + `"><button class="btn ghost small" type="submit">Revoke</button></form>`
			}
			addr := template.HTMLEscapeString(d.IP)
			if addr == "" {
				addr = `<span class="muted">unassigned</span>`
			}
			circle := `<form method="post" action="/admin/devices"><input type="hidden" name="action" value="circle"><input type="hidden" name="id" value="` + template.HTMLEscapeString(d.ID) + `"><input name="circle" value="` + template.HTMLEscapeString(circleOf(d)) + `" size="8"><button class="btn ghost small" type="submit">Set</button></form>`
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%s</td><td><span class="pill %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				deviceCell, circle, class, esc(state), build, reportCell, pollCell, addr, action)
		}
		b.WriteString(`</tbody></table></div>`)
	}
	s.renderNav(w, true, "devices", "Devices", b.String())
}

// deviceState is the one place that decides how healthy a device looks.
//
// The update check runs every minute and heartbeats, so its recency says
// whether the machine is alive at all. The report says whether what is running
// actually works. Together they answer the three questions an operator has:
// is it off, is it polling but broken, or is it fine.
func (s *server) deviceState(d device) (label, class, build, reportCell, pollCell string) {
	reportCell = `<span class="muted">never</span>`
	pollCell = `<span class="muted">never</span>`

	rep, hasReport := s.latestReport(d.PubKey)
	hb, hasHeartbeat := s.latestHeartbeat(d.PubKey)

	if hasReport {
		l, c := effectiveStatus(rep.Report)
		reportCell = fmt.Sprintf(`<span class="pill %s">%s</span><span class="cell-sub">%s</span>`,
			c, esc(l), esc(timeAgo(rep.Received)))
		build = rep.Report.Version
	}
	if hasHeartbeat {
		pollCell = esc(timeAgo(hb.Last))
		if build == "" {
			build = hb.Version
		}
	}

	switch {
	case d.Status != "bound":
		return "invite", "", build, reportCell, pollCell
	case !hasReport && !hasHeartbeat:
		return "never installed", "warn", build, reportCell, pollCell
	case hasHeartbeat && within(hb.Last, 10*time.Minute) && hasReport && within(rep.Received, 30*time.Minute):
		if rep.Report.Status == "functional" {
			return "healthy", "ok", build, reportCell, pollCell
		}
		return "degraded", "warn", build, reportCell, pollCell
	case hasHeartbeat && within(hb.Last, 10*time.Minute):
		return "polling", "warn", build, reportCell, pollCell
	case hasReport && within(rep.Received, 24*time.Hour):
		// No heartbeat, but a recent report: either the build predates
		// heartbeats or its updater is not running. Either way the machine was
		// seen today, so it is not off.
		return "no heartbeat", "warn", build, reportCell, pollCell
	default:
		return "off", "bad", build, reportCell, pollCell
	}
}

// within reports whether a timestamp is newer than age.
func within(ts string, age time.Duration) bool {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return false
	}
	return time.Since(t) <= age
}
