package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
)

// Detail views: one entity per page, linked from the list rows.

func pathID(path, prefix string) (string, bool) {
	id := strings.TrimPrefix(path, prefix)
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

func backLink(href, label string) string {
	return fmt.Sprintf(`<p><a class="btn ghost small" href="%s">&larr; %s</a></p>`, href, label)
}

func detailList(pairs ...string) string {
	var b strings.Builder
	b.WriteString(`<div class="card tight"><dl class="kv">`)
	for i := 0; i+1 < len(pairs); i += 2 {
		fmt.Fprintf(&b, `<dt>%s</dt><dd>%s</dd>`, pairs[i], pairs[i+1])
	}
	b.WriteString(`</dl></div>`)
	return b.String()
}

func (s *server) adminApplicationDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id, ok := pathID(r.URL.Path, "/admin/applications/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.appsMu.Lock()
	app, found := s.applicationByID(id)
	s.appsMu.Unlock()
	if !found {
		http.NotFound(w, r)
		return
	}
	deviceStatus := s.deviceStatuses()
	chip, class := "waiting", "new"
	switch {
	case app.ProvisionError != "":
		chip, class = "preparation failed", "bad"
	case app.DeviceID != "" && deviceStatus[app.DeviceID] == "bound":
		chip, class = "installed", "ok"
	case app.DeviceID != "":
		chip, class = "installer ready", "ok"
	case app.Reviewed:
		chip, class = "approved", ""
	}

	var b strings.Builder
	b.WriteString(backLink("/admin/applications", "Applications"))
	b.WriteString(`<div class="admin-head"><h1>` + esc(app.Name) + `</h1><span class="pill ` + class + `">` + chip + `</span></div>`)
	b.WriteString(adminSubnav("applications"))
	b.WriteString(detailList(
		"Status", `<span class="pill `+class+`">`+chip+`</span>`,
		"Device", esc(osLabel(app.OS, app.Arch)),
		"Submitted", esc(displayTime(app.Created)),
		"Reference", `<code>`+esc(app.ID)+`</code>`,
	))
	if app.Why != "" {
		fmt.Fprintf(&b, `<div class="card"><h2>Reason</h2><p>%s</p></div>`, esc(app.Why))
	}
	if app.DeviceID != "" {
		fetched := `<span class="muted">not downloaded yet</span>`
		if app.SetupDownloads > 0 {
			fetched = fmt.Sprintf(`%d &times; <span class="cell-sub">last %s</span>`,
				app.SetupDownloads, esc(displayTime(app.SetupDownloaded)))
		}
		inst := detailList(
			"Device", `<a href="/admin/devices/`+esc(app.DeviceID)+`"><code>`+esc(app.DeviceID)+`</code></a>`,
			"Token", `<code>`+esc(app.EnrollToken)+`</code> <button type="button" class="btn ghost small" data-copy="`+esc(app.EnrollToken)+`">Copy</button>`,
			"Prepared", esc(displayTime(app.ProvisionedAt)),
			"Setup archive", fetched,
		)
		b.WriteString(inst)
	}
	if app.LinkedUser != "" {
		b.WriteString(detailList("Linked login", `<code>`+esc(app.LinkedUser)+`</code>`))
	}
	if app.ProvisionError != "" {
		fmt.Fprintf(&b, `<div class="alert error">%s</div>`, esc(app.ProvisionError))
	}

	b.WriteString(`<div class="card"><h2>Actions</h2><div class="row-actions">`)
	if !app.Reviewed || (app.DeviceID == "" && app.ProvisionError == "") {
		fmt.Fprintf(&b, `<form method="post" action="/admin/applications"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s"><input type="hidden" name="action" value="approve"><button class="btn" type="submit">Approve &amp; prepare</button></form>`, s.csrfToken(r), esc(app.ID))
	}
	if app.ProvisionError != "" {
		fmt.Fprintf(&b, `<form method="post" action="/admin/applications"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s"><input type="hidden" name="action" value="retry"><button class="btn ghost" type="submit">Retry</button></form>`, s.csrfToken(r), esc(app.ID))
	}
	if app.DeviceID != "" {
		fmt.Fprintf(&b, `<form method="post" action="/admin/applications" onsubmit="return confirm('Reissue the setup invite? The same status link will serve a fresh token and the current installer.')"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s"><input type="hidden" name="action" value="reissue"><button class="btn ghost" type="submit">Reissue invite</button></form>`, s.csrfToken(r), esc(app.ID))
	}
	fmt.Fprintf(&b, `<form method="post" action="/admin/applications" onsubmit="return confirm('Delete this application?')"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s"><input type="hidden" name="action" value="delete"><button class="btn danger" type="submit">Delete</button></form>`, s.csrfToken(r), esc(app.ID))
	b.WriteString(`</div></div>`)
	s.renderNav(w, true, "applications", app.Name, b.String())
}

func (s *server) adminDeviceDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/admin/devices/")
	if id, isSupport := strings.CutSuffix(raw, "/support"); isSupport {
		s.serveDeviceSupport(w, r, id)
		return
	}
	id, ok := pathID(r.URL.Path, "/admin/devices/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.devicesMu.Lock()
	reg, err := loadDevices(s.devicesPath())
	s.devicesMu.Unlock()
	if err != nil {
		http.Error(w, "device registry unreadable", http.StatusInternalServerError)
		return
	}
	var dev *device
	for i := range reg.Devices {
		if reg.Devices[i].ID == id {
			dev = &reg.Devices[i]
			break
		}
	}
	if dev == nil {
		http.NotFound(w, r)
		return
	}
	class := ""
	if dev.Status == "bound" {
		class = "ok"
	}
	var b strings.Builder
	b.WriteString(backLink("/admin/devices", "Devices"))
	b.WriteString(`<div class="admin-head"><h1>` + esc(dev.Label) + `</h1><span class="pill ` + class + `">` + esc(dev.Status) + `</span></div>`)
	b.WriteString(adminSubnav("devices"))
	pairs := []string{
		"Device", `<code>` + esc(dev.ID) + `</code>`,
		"Last report", s.reportCell(dev.PubKey),
		"Status", esc(dev.Status),
		"Address", esc(dev.IP),
		"Created", esc(dev.Created),
		"Expires", esc(dev.Expires),
	}
	if dev.BoundAt != "" {
		pairs = append(pairs, "Bound", esc(dev.BoundAt))
	}
	if dev.PubKey != "" {
		pairs = append(pairs, "Key fingerprint", `<code>`+esc(fingerprint(dev.PubKey))+`</code>`)
		pairs = append(pairs, "Public key", `<code>`+esc(dev.PubKey)+`</code>`)
	}
	if dev.RelayUser != "" {
		pairs = append(pairs, "Relay user", `<a href="/admin/relay/`+esc(dev.RelayUser)+`"><code>`+esc(dev.RelayUser)+`</code></a>`)
	}
	if _, meta, ok := s.latestSupport(dev.PubKey); ok && dev.PubKey != "" {
		when := esc(displayTime(meta.Received))
		size := fmt.Sprintf("%.0f KB", float64(meta.Bytes)/1024)
		pairs = append(pairs, "Support bundle",
			`<a href="/admin/devices/`+esc(dev.ID)+`/support">download</a> <span class="cell-sub">`+esc(size)+` &middot; `+when+`</span>`)
	} else if dev.PubKey != "" {
		pairs = append(pairs, "Support bundle", `<span class="muted">none uploaded</span>`)
	}
	if dev.Platform != "" {
		pairs = append(pairs, "Platform", esc(dev.Platform+"/"+dev.Arch))
	}
	b.WriteString(detailList(pairs...))
	fmt.Fprintf(&b, `<div class="card"><h2>Actions</h2><div class="row-actions"><form method="post" action="/admin/devices" onsubmit="return confirm('Revoke this device? It disconnects immediately.')"><input type="hidden" name="action" value="revoke"><input type="hidden" name="id" value="%s"><button class="btn danger" type="submit">Revoke device</button></form></div></div>`, esc(dev.ID))
	s.renderNav(w, true, "devices", dev.Label, b.String())
}

func (s *server) adminRelayDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	user, ok := pathID(r.URL.Path, "/admin/relay/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	users, err := readRelayAuth(relayAuthFilePath())
	if err != nil {
		http.Error(w, "relay auth file is not readable", http.StatusInternalServerError)
		return
	}
	pass, found := users[user]
	if !found {
		http.NotFound(w, r)
		return
	}
	usage := readRelayUsage(relayUsageFilePath())
	relayed := "no data"
	if bytes, ok := usage[user]; ok {
		relayed = fmt.Sprintf("%.0f MB", float64(bytes)/(1<<20))
	}
	var b strings.Builder
	b.WriteString(backLink("/admin/relay", "Relay"))
	b.WriteString(`<div class="admin-head"><h1>` + esc(user) + `</h1></div>`)
	b.WriteString(adminSubnav("relay"))
	b.WriteString(detailList(
		"Relay user", `<code>`+esc(user)+`</code>`,
		"Relayed", esc(relayed),
		"Password", `<input id="relay-pass" type="password" value="`+esc(pass)+`" readonly style="max-width:22rem"> <button type="button" class="btn ghost small" data-reveal="relay-pass">Show</button>`,
	))
	// data-reveal targets an id; give the field one.
	b.WriteString(`<div class="card"><h2>Actions</h2><div class="row-actions">`)
	fmt.Fprintf(&b, `<form method="post" action="/admin/relay"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="user" value="%s"><input type="hidden" name="action" value="rotate"><button class="btn ghost" type="submit">Rotate password</button></form>`, s.csrfToken(r), esc(user))
	fmt.Fprintf(&b, `<form method="post" action="/admin/relay" onsubmit="return confirm('Revoke relay access for this device?')"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="user" value="%s"><input type="hidden" name="action" value="revoke"><button class="btn danger" type="submit">Revoke</button></form>`, s.csrfToken(r), esc(user))
	b.WriteString(`</div></div>`)
	s.renderNav(w, true, "relay", user, b.String())
}

func (s *server) adminUserDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	name, ok := pathID(r.URL.Path, "/admin/users/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.usersMu.Lock()
	users := s.loadUsers()
	u, found := users[name]
	s.usersMu.Unlock()
	if !found {
		http.NotFound(w, r)
		return
	}
	password := `<span class="muted">hash only</span>`
	if u.Password != "" {
		password = `<input id="login-pass" type="password" value="` + esc(u.Password) + `" readonly style="max-width:22rem"> <button type="button" class="btn ghost small" data-reveal="login-pass">Show</button>`
	}
	var b strings.Builder
	b.WriteString(backLink("/admin/users", "Logins"))
	b.WriteString(`<div class="admin-head"><h1>` + esc(name) + `</h1></div>`)
	b.WriteString(adminSubnav("users"))
	b.WriteString(detailList(
		"Login", `<code>`+esc(name)+`</code>`,
		"Label", esc(u.Label),
		"Installer", esc(u.Binary),
		"Platform", esc(u.OS+"/"+u.Arch),
		"Peer", esc(u.Peer),
		"Downloads", fmt.Sprintf("%d", u.Downloads),
		"Last download", esc(displayTime(u.LastDownload)),
		"Created", esc(displayTime(u.Created)),
		"Password", password,
	))
	b.WriteString(`<div class="card"><h2>Actions</h2><div class="row-actions">`)
	fmt.Fprintf(&b, `<form method="post" action="/admin/users"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="username" value="%s"><input type="hidden" name="action" value="reset"><button class="btn" type="submit">Reset password</button></form>`, s.csrfToken(r), esc(name))
	fmt.Fprintf(&b, `<form method="post" action="/admin/users" onsubmit="return confirm('Revoke this login, delete the installer, and remove the WireGuard peer?')"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="username" value="%s"><input type="hidden" name="action" value="revoke"><button class="btn danger" type="submit">Revoke</button></form>`, s.csrfToken(r), esc(name))
	b.WriteString(`</div></div>`)
	s.renderNav(w, true, "users", name, b.String())
}

// serveDeviceSupport streams the newest uploaded bundle for one device.
func (s *server) serveDeviceSupport(w http.ResponseWriter, r *http.Request, id string) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.devicesMu.Lock()
	reg, err := loadDevices(s.devicesPath())
	s.devicesMu.Unlock()
	if err != nil {
		http.Error(w, "device registry unreadable", http.StatusInternalServerError)
		return
	}
	for _, dev := range reg.Devices {
		if dev.ID != id {
			continue
		}
		file, _, ok := s.latestSupport(dev.PubKey)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(file)+`"`)
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, file)
		return
	}
	http.NotFound(w, r)
}
