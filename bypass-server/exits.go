package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// bypass-server is its own module, so it reads the router's files directly.
// The schema mirrors internal/exitroute; keep them in step.
type exitEntry struct {
	ID          string `json:"id"`
	Label       string `json:"label,omitempty"`
	PubKey      string `json:"pubkey"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority,omitempty"`
	MaxPrefixes int    `json:"max_prefixes,omitempty"`
	Host        string `json:"host,omitempty"`
	Network     string `json:"network,omitempty"`
	Note        string `json:"note,omitempty"`
}

type exitRegistry struct {
	Version int         `json:"version"`
	Exits   []exitEntry `json:"exits"`
}

type exitSite struct {
	State    string `json:"state"`
	Exit     string `json:"exit,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Verified string `json:"verified,omitempty"`
}

type exitLive struct {
	ID        string `json:"id"`
	Label     string `json:"label,omitempty"`
	Enabled   bool   `json:"enabled"`
	Healthy   bool   `json:"healthy"`
	Handshake int64  `json:"handshake,omitempty"`
	Prefixes  int    `json:"prefixes"`
	Sites     int    `json:"sites"`
	Error     string `json:"error,omitempty"`
}

type exitStatus struct {
	Updated     time.Time           `json:"updated"`
	Sites       map[string]exitSite `json:"sites"`
	Assignments map[string]string   `json:"assignments"`
	Exits       []exitLive          `json:"exits"`
	Unserved    []string            `json:"unserved"`
	AllDown     bool                `json:"all_down,omitempty"`
}

func exitRegistryPath() string {
	if p := os.Getenv("EGRESS_EXIT_REGISTRY"); p != "" {
		return p
	}
	return "/var/lib/bypass/exits.json"
}

func exitStatusPath() string {
	if p := os.Getenv("EGRESS_EXIT_STATUS"); p != "" {
		return p
	}
	return "/var/lib/egress-exit/status.json"
}

func loadExitRegistry(path string) (exitRegistry, error) {
	reg := exitRegistry{Version: 1}
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

func saveExitRegistry(path string, reg exitRegistry) error {
	reg.Version = 1
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadExitStatus(path string) (exitStatus, error) {
	var status exitStatus
	data, err := os.ReadFile(path)
	if err != nil {
		return status, err
	}
	err = json.Unmarshal(data, &status)
	if status.Sites == nil {
		status.Sites = map[string]exitSite{}
	}
	if status.Assignments == nil {
		status.Assignments = map[string]string{}
	}
	return status, err
}

// exitDomainState is what the router knows per domain, for decorating the feed.
func (s *server) exitDomainState() map[string]exitSite {
	if _, err := os.Stat(exitStatusPath()); err != nil {
		return nil
	}
	status, err := loadExitStatus(exitStatusPath())
	if err != nil {
		return nil
	}
	return status.Sites
}

// adminExits shows the exit registry and what the router is doing with it.
func (s *server) adminExits(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		id := r.FormValue("id")
		enable := r.FormValue("action") == "enable"
		reg, err := loadExitRegistry(exitRegistryPath())
		if err != nil {
			http.Error(w, "could not read the exit registry: "+err.Error(), http.StatusInternalServerError)
			return
		}
		found := false
		for i := range reg.Exits {
			if reg.Exits[i].ID == id {
				reg.Exits[i].Enabled = enable
				found = true
			}
		}
		if !found {
			http.Error(w, "no exit named "+id, http.StatusNotFound)
			return
		}
		if err := saveExitRegistry(exitRegistryPath(), reg); err != nil {
			http.Error(w, "could not write the exit registry: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/exits", http.StatusSeeOther)
		return
	}

	reg, regErr := loadExitRegistry(exitRegistryPath())
	status, statusErr := loadExitStatus(exitStatusPath())

	var b strings.Builder
	b.WriteString(`<h1>Exits</h1>
<p>Sites the cloud exit refuses are routed through the first enrolled exit that serves them. Prefixes move automatically when an exit stops answering or a site starts working again. Changes here take effect on the router's next cycle.</p>`)
	if regErr != nil {
		fmt.Fprintf(&b, `<p class="warn">Could not read the registry: %s</p>`, template.HTMLEscapeString(regErr.Error()))
	}
	if statusErr != nil {
		b.WriteString(`<p class="muted">No router status yet. Either no exit is enrolled or the router has not completed a cycle.</p>`)
	} else if status.AllDown && len(reg.Exits) > 0 {
		b.WriteString(`<p class="warn">Every enrolled exit is unreachable. Blocked sites fall back to the cloud exit until one answers.</p>`)
	}
	if len(reg.Exits) == 0 {
		b.WriteString(`<p>Enroll one on Aegis with <code>./deploy/add-exit.sh --id hestia --host hestia</code>.</p>`)
	} else {
		byID := map[string]exitLive{}
		for _, e := range status.Exits {
			byID[e.ID] = e
		}
		b.WriteString(`<table><thead><tr><th>Exit</th><th>Host</th><th>State</th><th>Last handshake</th><th>Prefixes</th><th>Sites</th><th></th></tr></thead><tbody>`)
		for _, exit := range reg.Exits {
			live := byID[exit.ID]
			state := "disabled"
			if exit.Enabled {
				state = "enabled"
				if live.Healthy {
					state = "healthy"
				} else if live.ID != "" {
					state = "no handshake"
				}
			}
			handshake := "never"
			if live.Handshake > 0 {
				handshake = time.Since(time.Unix(live.Handshake, 0)).Round(time.Second).String() + " ago"
			}
			action, label := "disable", "Disable"
			if !exit.Enabled {
				action, label = "enable", "Enable"
			}
			fmt.Fprintf(&b, `<tr><td><code>%s</code><br><span class="muted">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td><form method="post" action="/admin/exits"><input type="hidden" name="id" value="%s"><input type="hidden" name="action" value="%s"><button type="submit">%s</button></form></td></tr>`,
				template.HTMLEscapeString(exit.ID), template.HTMLEscapeString(exit.Label),
				template.HTMLEscapeString(exit.Host), template.HTMLEscapeString(state),
				template.HTMLEscapeString(handshake), live.Prefixes, live.Sites,
				template.HTMLEscapeString(exit.ID), action, label)
		}
		b.WriteString(`</tbody></table>`)
	}

	if len(status.Assignments) > 0 {
		prefixes := make([]string, 0, len(status.Assignments))
		for prefix := range status.Assignments {
			prefixes = append(prefixes, prefix)
		}
		sort.Strings(prefixes)
		b.WriteString(`<h2>Routed prefixes</h2><table><thead><tr><th>Prefix</th><th>Exit</th></tr></thead><tbody>`)
		for _, prefix := range prefixes {
			fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%s</td></tr>`,
				template.HTMLEscapeString(prefix), template.HTMLEscapeString(status.Assignments[prefix]))
		}
		b.WriteString(`</tbody></table>`)
	}
	if len(status.Unserved) > 0 {
		b.WriteString(`<h2>Unserved</h2><p>These are blocked here, refused by the cloud exit, and refused by every exit that answered.</p><ul>`)
		for _, domain := range status.Unserved {
			fmt.Fprintf(&b, `<li><code>%s</code></li>`, template.HTMLEscapeString(domain))
		}
		b.WriteString(`</ul>`)
	}
	if !status.Updated.IsZero() {
		fmt.Fprintf(&b, `<p class="muted">Router updated %s.</p>`, template.HTMLEscapeString(status.Updated.Local().Format("2006-01-02 15:04:05")))
	}
	s.renderNav(w, true, "exits", "Exits", b.String())
}
