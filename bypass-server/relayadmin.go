package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
)

// Relay credential administration. The relay's auth file is owned by this
// server's user and readable by the relay's group, so revocation and rotation
// take effect on the relay's next reload without a restart or SSH.

const relayAuthPath = "/etc/egress-socks/auth"

const relayUsagePath = "/var/lib/egress-socks/usage.json"

func readRelayAuth(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	users := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if user, pass, ok := strings.Cut(line, ":"); ok && user != "" && pass != "" {
			users[user] = pass
		}
	}
	return users, nil
}

func writeRelayAuth(path string, users map[string]string) error {
	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# managed by bypass-server; relay reloads on change\n")
	for _, name := range names {
		fmt.Fprintf(&b, "%s:%s\n", name, users[name])
	}
	// Write in place so the file keeps its owner and group: the relay runs as
	// a different user and reads it through group permission.
	return os.WriteFile(path, []byte(b.String()), 0640)
}

func readRelayUsage(path string) map[string]int64 {
	users := map[string]int64{}
	data, err := os.ReadFile(path)
	if err != nil {
		return users
	}
	var payload struct {
		Users map[string]int64 `json:"users"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return users
	}
	return payload.Users
}

func (s *server) adminRelay(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
		if err := r.ParseForm(); err != nil || !s.checkCSRF(r) {
			http.Error(w, "bad request", http.StatusForbidden)
			return
		}
		users, err := readRelayAuth(relayAuthPath)
		if err != nil {
			http.Error(w, "relay auth file is not readable", http.StatusInternalServerError)
			return
		}
		user := strings.TrimSpace(r.FormValue("user"))
		switch r.FormValue("action") {
		case "revoke":
			delete(users, user)
		case "rotate":
			if _, ok := users[user]; ok {
				var b [18]byte
				if _, err := rand.Read(b[:]); err == nil {
					users[user] = base64.RawURLEncoding.EncodeToString(b[:])
				}
			}
		default:
			http.Error(w, "bad action", http.StatusBadRequest)
			return
		}
		if err := writeRelayAuth(relayAuthPath, users); err != nil {
			http.Error(w, "could not write relay credentials", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/relay", http.StatusSeeOther)
		return
	}

	users, err := readRelayAuth(relayAuthPath)
	usage := readRelayUsage(relayUsagePath)
	var b strings.Builder
	b.WriteString(`<div class="admin-head"><h1>Relay</h1></div>`)
	b.WriteString(adminSubnav("relay"))
	b.WriteString(`<p class="muted">Per-device SOCKS credentials. Revoking one stops that device's relay access on the next reload (within 30 seconds) without touching anyone else. Rotating changes the password; the device must be rebuilt or re-enrolled to use it.</p>`)
	if err != nil {
		fmt.Fprintf(&b, `<div class="alert error">Cannot read %s: %s</div>`, esc(relayAuthPath), esc(err.Error()))
		s.renderNav(w, true, "admin", "Relay", b.String())
		return
	}
	b.WriteString(`<div class="table-wrap compact"><table><thead><tr><th>Relay user</th><th>Relayed</th><th></th></tr></thead><tbody>`)
	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		relayed := `<span class="muted">no data</span>`
		if bytes, ok := usage[name]; ok {
			relayed = fmt.Sprintf("%.0f MB", float64(bytes)/(1<<20))
		}
		fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%s</td><td><div class="row-actions">
<form method="post" action="/admin/relay"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="user" value="%s"><input type="hidden" name="action" value="rotate"><button class="btn ghost small" type="submit">Rotate</button></form>
<form method="post" action="/admin/relay" onsubmit="return confirm('Revoke relay access for this device?')"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="user" value="%s"><input type="hidden" name="action" value="revoke"><button class="btn danger small" type="submit">Revoke</button></form>
</div></td></tr>`,
			esc(name), relayed, s.csrfToken(r), esc(name), s.csrfToken(r), esc(name))
	}
	b.WriteString(`</tbody></table></div>`)
	s.renderNav(w, true, "admin", "Relay", b.String())
}
