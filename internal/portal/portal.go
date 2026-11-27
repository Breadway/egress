// Package portal serves the local page that explains what egress is doing
// with the sites you cannot open.
//
// It binds loopback only, keeps no state of its own, and reads a snapshot from
// the supervisor each request. It answers while the tunnel is down, which is
// the point: when egress cannot reach anything, this page is the one thing on
// the machine that can still say why.
package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Domain is one blocked site as the page shows it.
type Domain struct {
	Name      string
	Evidence  string
	ServedBy  string
	Unserved  bool
	LastProbe time.Time
	Checked   string // rendered form of LastProbe
}

// Snapshot is what the page renders.
type Snapshot struct {
	Generated time.Time
	Network   string
	Version   string
	Online    bool
	Tunnel    string
	Domains   []Domain
}

// Serve listens on addr until ctx is cancelled. Extra handlers are mounted
// under /api/v1/ on the same listener; the GUI API is the only caller.
func Serve(ctx context.Context, addr string, snap func() Snapshot, logf func(string, ...any), extra ...http.Handler) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("portal listen %s: %w", addr, err)
	}
	srv := &http.Server{Handler: newHandler(snap, extra...), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	logf("portal: serving on http://%s/", addr)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// newHandler serves the page and nothing else, plus any mounted API.
func newHandler(snap func() Snapshot, extra ...http.Handler) http.Handler {
	mux := http.NewServeMux()
	for _, h := range extra {
		mux.Handle("/api/v1/", h)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		render(w, snap())
	})
	// The tray has no proxy to ask any more; this is its status source.
	mux.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) {
		s := snap()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(struct {
			Version string `json:"version"`
			Network string `json:"network"`
			Online  bool   `json:"online"`
			Blocked int    `json:"blocked"`
		}{Version: s.Version, Network: s.Network, Online: s.Online, Blocked: len(s.Domains)})
	})
	return mux
}

var page = template.Must(template.New("portal").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>egress</title>
<style>
:root { color-scheme: light dark; }
body { font: 15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; margin: 0 auto; max-width: 56rem; padding: 2rem 1.25rem 4rem; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
.sub { color: #888; margin: 0 0 1.5rem; }
.banner { border-radius: .5rem; padding: .75rem 1rem; margin: 0 0 1.5rem; }
.banner.ok { background: #1b5e2033; border: 1px solid #2e7d32; }
.banner.off { background: #b71c1c22; border: 1px solid #b71c1c; }
.banner.warn { background: #ed6c0222; border: 1px solid #ed6c02; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: .45rem .5rem; border-bottom: 1px solid #8884; vertical-align: top; }
th { font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; color: #888; }
td.name { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.pill { display: inline-block; border-radius: 999px; padding: .05rem .5rem; font-size: .8rem; border: 1px solid #8886; white-space: nowrap; }
.pill.exit { background: #2e7d3222; border-color: #2e7d32; }
.pill.unserved { background: #b71c1c22; border-color: #b71c1c; }
.pill.direct { background: #1976d222; border-color: #1976d2; }
footer { margin-top: 2rem; color: #888; font-size: .85rem; }
</style>
</head>
<body>
<h1>egress</h1>
<p class="sub">{{.Network}}{{if .Version}} · egress {{.Version}}{{end}} · updated {{.GeneratedLabel}}</p>
{{if .Online}}
<div class="banner ok">Connected. Blocked sites are routed through the tunnel; each one below says how it is being reached.</div>
{{else}}
<div class="banner off"><strong>egress is offline.</strong> The tunnel is not up, so nothing can be routed right now. This is the last state this machine knows, from before the connection dropped.</div>
{{end}}
{{if .UnservedCount}}
<div class="banner warn">{{.UnservedCount}} blocked site{{if ne .UnservedCount 1}}s{{end}} cannot be routed through any available exit. {{if .Online}}Their traffic stays on your normal connection, so they are marked direct rather than tunnelled.{{else}}Their traffic stays on your normal connection until the tunnel is back.{{end}}</div>
{{end}}
<table>
<thead><tr><th>site</th><th>status</th><th>why</th><th>checked</th></tr></thead>
<tbody>
{{range .Domains}}
<tr>
<td class="name">{{.Name}}</td>
<td>{{if .Unserved}}<span class="pill direct">direct</span>{{else if .ServedBy}}<span class="pill exit">via {{.ServedBy}}</span>{{else}}<span class="pill direct">cloud exit</span>{{end}}</td>
<td>{{.Evidence}}{{if .Unserved}} · every exit refused it; traffic uses your normal connection{{else if .ServedBy}} · the cloud exit was refused, {{.ServedBy}} serves it{{end}}</td>
<td>{{.Checked}}</td>
</tr>
{{else}}
<tr><td colspan="4">Nothing is blocked on this network right now.</td></tr>
{{end}}
</tbody>
</table>
<footer>
<p>This page is served by egress on this machine at <code>http://127.0.0.1:7280/</code>. It is reachable even when the tunnel is not.</p>
<p>A site marked <em>direct</em> is blocked by the network and refused by every exit egress could try, including the cloud exit, so its traffic stays on your normal connection instead of a tunnel. That is the route in use, not a claim that the site is unreachable; the next check happens automatically.</p>
</footer>
</body>
</html>
`))

type view struct {
	Snapshot
	Domains        []Domain
	UnservedCount  int
	GeneratedLabel string
}

func render(w http.ResponseWriter, snap Snapshot) {
	domains := append([]Domain(nil), snap.Domains...)
	sort.Slice(domains, func(i, j int) bool {
		if domains[i].Unserved != domains[j].Unserved {
			return domains[i].Unserved
		}
		return strings.ToLower(domains[i].Name) < strings.ToLower(domains[j].Name)
	})
	unserved := 0
	for _, d := range domains {
		if d.Unserved {
			unserved++
		}
	}
	if snap.Generated.IsZero() {
		snap.Generated = time.Now()
	}
	data := view{
		Snapshot:       snap,
		Domains:        domains,
		UnservedCount:  unserved,
		GeneratedLabel: snap.Generated.UTC().Format("2006-01-02 15:04:05 MST"),
	}
	if data.Network == "" {
		data.Network = "network unknown"
	}
	for i := range data.Domains {
		if data.Domains[i].LastProbe.IsZero() {
			data.Domains[i].Checked = "never"
		} else {
			data.Domains[i].Checked = data.Domains[i].LastProbe.UTC().Format("15:04:05 MST")
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = page.Execute(w, data)
}
