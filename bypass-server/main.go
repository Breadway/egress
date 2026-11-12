// Command bypass-server runs on Aegis behind Caddy at bypass.breadway.dev.
//
// Enrollment works without any out-of-band contact:
//
//   - a visitor applies with a name and why they need access, and gets a
//     secret status link to bookmark;
//   - the admin provisions by hand (new-device.sh), publishes the installer
//     (publish-device.sh, optionally linked to the application), and reviews
//     the application in the admin UI;
//   - the applicant's status link then offers a set-your-own-password form,
//     after which the username + chosen password downloads the installer.
//
// There are no user sessions: POST /download verifies the password and
// returns the file in the same response. Status links are capability URLs
// (128-bit claim tokens, stored hashed). The admin UI uses a signed session
// cookie (per-login nonce) plus per-session CSRF tokens; the machine API (used by
// publish-device.sh) keeps bearer-token auth. Secrets and client IPs are
// never logged. The only external module is x/crypto.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultAddr     = "127.0.0.1:7220"
	defaultStateDir = "/var/lib/bypass"

	maxFormBody    = 64 << 10
	bcryptCost     = 12
	applyPerHour   = 10
	authFailsMax   = 10
	authWindow     = 10 * time.Minute
	sessionTTL     = 12 * time.Hour
	sessionCookie  = "bypass_admin"
	maxUsernameLen = 32
	claimTTL       = 15 * time.Minute
)

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
var validID = regexp.MustCompile(`^[0-9a-f]{16}$`)
var validClaim = regexp.MustCompile(`^[0-9a-f]{32}$`)

type user struct {
	Hash string `json:"hash"`
	// Password is the issued password in recoverable form so the applicant's
	// status page can show it and offer a one-click download link. The file
	// stays 0600 and readable only by the service account; Caddy discards
	// access logs so the link never lands in a log. Anyone holding the
	// status link already has full access to this account, so the link adds
	// no new capability beyond it.
	Password string `json:"password,omitempty"`
	Binary   string `json:"binary"`
	Label    string `json:"label"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Peer     string `json:"peer,omitempty"`
	Created  string `json:"created"`
	// Downloads counts completed installer downloads.
	Downloads    int    `json:"downloads,omitempty"`
	LastDownload string `json:"last_download,omitempty"`
}

type application struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Why            string `json:"why"`
	OS             string `json:"os,omitempty"`
	Arch           string `json:"arch,omitempty"`
	ClaimHash      string `json:"claim"`
	LinkedUser     string `json:"user"`
	Created        string `json:"created"`
	Reviewed       bool   `json:"reviewed"`
	ClaimedAt      string `json:"claimed_at,omitempty"`
	ProvisionError string `json:"provision_error,omitempty"`
}

type server struct {
	state     string
	adminUser string
	adminHash []byte
	token     string
	dummy     []byte
	mux       *http.ServeMux
	mtx       sync.Mutex
	usersMu   sync.Mutex
	appsMu    sync.Mutex
	fails     map[string][]time.Time
	applys    map[string][]time.Time
	reports   map[string][]time.Time
	splits    map[string][]time.Time
	feedMu    sync.Mutex
}

func main() {
	hashOnly := flag.String("hash", "", "print a bcrypt hash of the given password and exit")
	flag.Parse()
	if *hashOnly != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*hashOnly), bcryptCost)
		if err != nil {
			log.Fatalf("hash: %v", err)
		}
		fmt.Println(string(hash))
		return
	}

	addr := envOr("BYPASS_ADDR", defaultAddr)
	state := envOr("BYPASS_STATE", defaultStateDir)
	token := os.Getenv("BYPASS_ADMIN_TOKEN")
	adminUser := envOr("BYPASS_ADMIN_USER", "admin")
	adminHash := os.Getenv("BYPASS_ADMIN_PASSWORD_HASH")
	if token == "" {
		log.Fatal("BYPASS_ADMIN_TOKEN is not set")
	}
	if adminHash == "" {
		log.Fatal("BYPASS_ADMIN_PASSWORD_HASH is not set")
	}
	for _, dir := range []string{state, filepath.Join(state, "applications"), filepath.Join(state, "binaries")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatalf("state dir: %v", err)
		}
	}

	dummy, err := bcrypt.GenerateFromPassword([]byte("bypass-server unknown-user dummy"), bcryptCost)
	if err != nil {
		log.Fatalf("dummy hash: %v", err)
	}

	s := &server{
		state: state, adminUser: adminUser, adminHash: []byte(adminHash),
		token: token, dummy: dummy,
		fails: map[string][]time.Time{}, applys: map[string][]time.Time{},
		reports: map[string][]time.Time{},
		splits:  map[string][]time.Time{},
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/", s.landing)
	s.mux.HandleFunc("/apply", s.apply)
	s.mux.HandleFunc("/status", s.status)
	s.mux.HandleFunc("/download", s.download)
	s.mux.HandleFunc("/admin/login", s.adminLogin)
	s.mux.HandleFunc("/admin/logout", s.adminLogout)
	s.mux.HandleFunc("/admin", s.adminDash)
	s.mux.HandleFunc("/admin/applications", s.adminApplications)
	s.mux.HandleFunc("/admin/users", s.adminUsers)
	s.mux.HandleFunc("/admin/api/users", s.adminAddUser)
	s.mux.HandleFunc("/admin/api/link", s.adminLink)
	s.mux.HandleFunc("/api/report", s.apiReport)
	s.mux.HandleFunc("/api/blocked-report", s.apiBlockedReport)
	s.mux.HandleFunc("/api/seed", s.apiSeed)
	s.mux.HandleFunc("/admin/reports", s.adminReports)
	s.mux.HandleFunc("/admin/split", s.adminSplit)
	s.mux.HandleFunc("/admin/relay", s.adminRelay)
	s.mux.HandleFunc("/admin/api/pending", s.adminPending)
	s.mux.HandleFunc("/admin/api/claim", s.adminClaim)
	s.mux.HandleFunc("/admin/api/release", s.adminRelease)

	srv := &http.Server{
		Addr:         addr,
		Handler:      s,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Printf("listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.mux.ServeHTTP(w, r)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// clientIP returns the address Caddy saw: the last X-Forwarded-For entry,
// which is the one Caddy itself appended.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// allow records an event and reports whether the count within window is under max.
func (s *server) allow(bucket map[string][]time.Time, ip string, max int, window time.Duration) bool {
	now := time.Now()
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.evictBucketsLocked(bucket, window)
	events := bucket[ip][:0]
	for _, t := range bucket[ip] {
		if now.Sub(t) < window {
			events = append(events, t)
		}
	}
	if len(events) >= max {
		bucket[ip] = events
		return false
	}
	bucket[ip] = append(bucket[ip], now)
	return true
}

// evictBucketsLocked drops entries older than window from every bucket in
// the map, so distinct source addresses cannot grow it without bound on a
// public endpoint. Callers hold s.mtx.
func (s *server) evictBucketsLocked(bucket map[string][]time.Time, window time.Duration) {
	now := time.Now()
	for ip, events := range bucket {
		kept := events[:0]
		for _, t := range events {
			if now.Sub(t) < window {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(bucket, ip)
		} else {
			bucket[ip] = kept
		}
	}
}

func hashClaim(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// validWireGuardKey reports whether s is a 32-byte base64 key.
func validWireGuardKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

// randomPassword returns a 20-character URL-safe password.
func randomPassword() (string, error) {
	var b [15]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// revokePeer removes a peer from the live wg0 interface and from its config
// through a root-owned helper. The server itself runs unprivileged; sudo is
// restricted to this one script.
func revokePeer(peer string) error {
	if !validWireGuardKey(peer) {
		return fmt.Errorf("invalid peer key")
	}
	out, err := exec.Command("sudo", "-n", "/usr/local/sbin/bypass-revoke-peer", peer).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func esc(v string) string {
	return template.HTMLEscapeString(v)
}

// displayTime turns stored RFC3339 into something readable. Unknown formats
// are returned unchanged rather than hidden.
func displayTime(s string) string {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format("2 Jan 2006, 15:04")
	}
	return s
}

func osLabel(os, arch string) string {
	switch os {
	case "linux":
		return "Linux"
	case "darwin":
		if arch == "amd64" {
			return "macOS (Intel)"
		}
		return "macOS (Apple Silicon)"
	default:
		return "Windows"
	}
}

// splitOSArch maps an apply-form value to a build OS and arch. Unknown values
// fall back to Windows, matching the previous default.
func splitOSArch(v string) (string, string) {
	switch v {
	case "linux":
		return "linux", "amd64"
	case "mac-arm64":
		return "darwin", "arm64"
	case "mac-amd64":
		return "darwin", "amd64"
	default:
		return "windows", "amd64"
	}
}

// ------------------------------------------------------------------ layout ---

const siteCSS = `:root{
color-scheme:dark;
--bg:#0a0e13;--panel:#111823;--panel-2:#16202d;--line:#233044;--line-2:#31435c;
--ink:#e9eef6;--ink-dim:#9aabbd;--ink-faint:#6b7c90;
--accent:#6aa8ff;--accent-2:#2f6fd6;--ok:#3ddc97;--warn:#f5c451;--bad:#ff7b7b;
--radius:16px;--shadow:0 18px 50px -24px rgba(0,0,0,.85);
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:light){:root{
color-scheme:light;
--bg:#f4f6fa;--panel:#fff;--panel-2:#f7f9fc;--line:#e2e8f0;--line-2:#cbd5e1;
--ink:#101827;--ink-dim:#4a5a70;--ink-faint:#6b7c90;
--accent:#1f5fbf;--accent-2:#1f5fbf;--ok:#0f7a4d;--warn:#8a5a00;--bad:#b42323;
--shadow:0 18px 50px -30px rgba(16,24,39,.4)}}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font:16px/1.65 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
color:var(--ink);background:radial-gradient(900px 520px at 50% -12%,rgba(106,168,255,.12),transparent 70%),var(--bg);
-webkit-font-smoothing:antialiased;min-height:100vh}
.wrap{max-width:52rem;margin:0 auto;padding:0 1.25rem 4rem}
a{color:var(--accent)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.skip{position:absolute;left:-9999px;top:0;background:var(--panel);padding:.6rem 1rem;border-radius:0 0 10px 0;z-index:9}
.skip:focus{left:0}
header.site{display:flex;align-items:center;gap:1rem;padding:1.35rem 0;margin-bottom:2.2rem;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:.6rem;font-weight:750;color:var(--ink);text-decoration:none;letter-spacing:-.015em;font-size:1.02rem}
.brand svg{width:23px;height:23px;color:var(--accent);flex:none}
nav.main{margin-left:auto;display:flex;gap:.3rem;align-items:center;flex-wrap:wrap}
nav.main a{padding:.42rem .8rem;border-radius:9px;color:var(--ink-dim);text-decoration:none;font-size:.93rem;font-weight:550}
nav.main a:hover{color:var(--ink);background:var(--panel-2)}
nav.main a.active{color:var(--ink);background:var(--panel-2);box-shadow:inset 0 0 0 1px var(--line)}
.hero{padding:2.6rem 0 1.2rem}
.hero h1{font-size:clamp(2rem,5.2vw,3.1rem);line-height:1.08;letter-spacing:-.035em;margin:0 0 1rem;max-width:22ch}
.lede{font-size:1.1rem;color:var(--ink-dim);max-width:54ch;margin:0}
h1{font-size:1.65rem;letter-spacing:-.02em;line-height:1.2;margin:.2rem 0 .8rem}
h2{font-size:1.1rem;letter-spacing:-.01em;margin:0 0 .6rem}
p{margin:.6rem 0}
.muted{color:var(--ink-faint);font-size:.88rem}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:1.4rem 1.5rem;margin:1.1rem 0;box-shadow:var(--shadow)}
.card.tight{padding:1.1rem 1.2rem}
.cta-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin:2.2rem 0 1.4rem}
@media(max-width:660px){.cta-grid{grid-template-columns:1fr}.hero{padding-top:1.4rem}}
.cta{display:block;padding:1.35rem 1.4rem;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--ink);text-decoration:none;transition:transform .15s,border-color .15s,background .15s;box-shadow:var(--shadow)}
.cta:hover{transform:translateY(-2px);border-color:var(--line-2);background:var(--panel-2)}
.cta strong{display:block;font-size:1.12rem;letter-spacing:-.01em;margin-bottom:.25rem}
.cta span:last-child{display:block;color:var(--ink-dim);font-size:.92rem}
label{display:block;font-weight:650;font-size:.94rem;margin:1.15rem 0 .4rem}
input,textarea,select{width:100%;padding:.72rem .85rem;border-radius:10px;border:1px solid var(--line-2);background:var(--panel-2);color:var(--ink);font:inherit}
input:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(106,168,255,.18)}
textarea{resize:vertical;min-height:6.5rem}
.hint{display:block;color:var(--ink-faint);font-size:.84rem;margin-top:.35rem}
.hp{position:absolute;left:-9999px;width:1px;height:1px;opacity:0}
.field-row{display:flex;gap:.5rem;align-items:stretch}
.field-row input{flex:1 1 auto;min-width:0}
.actions{display:flex;gap:.6rem;align-items:center;margin-top:1.3rem;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.45rem;background:var(--accent-2);color:#fff;border:1px solid transparent;border-radius:10px;padding:.62rem 1.15rem;font:inherit;font-weight:650;font-size:.95rem;cursor:pointer;text-decoration:none;transition:filter .15s,background .15s,border-color .15s}
.btn:hover{filter:brightness(1.1)}
.btn.ghost{background:transparent;color:var(--ink-dim);border-color:var(--line-2)}
.btn.ghost:hover{color:var(--ink);border-color:var(--accent);filter:none}
.btn.danger{background:transparent;color:var(--bad);border-color:rgba(255,123,123,.45)}
.btn.danger:hover{background:rgba(255,123,123,.1);filter:none}
.btn.small{padding:.34rem .7rem;font-size:.83rem;border-radius:8px}
.alert{border-radius:12px;padding:.85rem 1rem;margin:1rem 0;border:1px solid;font-size:.94rem}
.alert.error{background:rgba(255,123,123,.09);border-color:rgba(255,123,123,.42);color:var(--bad)}
.alert.ok{background:rgba(61,220,151,.09);border-color:rgba(61,220,151,.38);color:var(--ok)}
.alert.info{background:rgba(106,168,255,.09);border-color:rgba(106,168,255,.32);color:var(--accent)}
.timeline{list-style:none;margin:1.6rem 0 0;padding:0;position:relative}
.timeline li{position:relative;padding:0 0 1.55rem 2.3rem}
.timeline li:before{content:"";position:absolute;left:.56rem;top:1.35rem;bottom:0;width:2px;background:var(--line)}
.timeline li:last-child{padding-bottom:0}
.timeline li:last-child:before{display:none}
.timeline .dot{position:absolute;left:0;top:.18rem;width:1.18rem;height:1.18rem;border-radius:50%;border:2px solid var(--line-2);background:var(--panel)}
.timeline li.done .dot{background:var(--ok);border-color:var(--ok)}
.timeline li.current .dot{border-color:var(--accent);box-shadow:0 0 0 4px rgba(106,168,255,.16)}
.timeline strong{display:block;font-size:.98rem}
.timeline p{margin:.15rem 0 0;color:var(--ink-dim);font-size:.9rem}
.linkbox{display:flex;gap:.55rem;align-items:stretch;margin:1rem 0;flex-wrap:wrap}
.linkbox code{flex:1 1 17rem;min-width:0;overflow-wrap:anywhere;background:var(--panel-2);border:1px solid var(--line-2);border-radius:10px;padding:.72rem .85rem;font-family:var(--mono);font-size:.84rem;line-height:1.45}
code{font-family:var(--mono);font-size:.88em;background:var(--panel-2);border:1px solid var(--line);border-radius:6px;padding:.08rem .38rem}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow);margin:1.1rem 0}
table{width:100%;border-collapse:collapse;font-size:.92rem}
th,td{text-align:left;padding:.78rem 1rem;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.09em;color:var(--ink-faint);background:var(--panel-2);font-weight:700;white-space:nowrap}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--panel-2)}
td form{display:inline-flex;gap:.35rem;align-items:center;margin:0}
td input{padding:.3rem .5rem;font-size:.83rem;border-radius:7px;width:9rem}
.row-actions{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center}
.why{max-width:26rem;overflow-wrap:anywhere}
.pill{display:inline-block;font-size:.74rem;font-weight:700;padding:.16rem .62rem;border-radius:999px;background:var(--panel-2);border:1px solid var(--line-2);color:var(--ink-dim);white-space:nowrap}
.pill.new{background:rgba(245,196,81,.13);border-color:rgba(245,196,81,.42);color:var(--warn)}
.pill.ok{background:rgba(61,220,151,.13);border-color:rgba(61,220,151,.42);color:var(--ok)}
.pill.bad{background:rgba(255,123,123,.13);border-color:rgba(255,123,123,.42);color:var(--bad)}
.pill.skip{background:var(--panel-2);border-color:var(--line);color:var(--ink-faint)}
.report-head{display:flex;flex-wrap:wrap;gap:.5rem .9rem;align-items:center}
.report-meta{color:var(--ink-dim);font-size:.88rem}
.cell-sub{display:block;color:var(--ink-dim);font-size:.82rem;margin-top:.18rem;font-weight:400}
a.cell-sub{text-decoration:none;color:var(--accent)}
a.cell-sub:hover{text-decoration:underline}
.err-snip{display:block;color:var(--bad);font-size:.82rem;margin-top:.25rem;overflow-wrap:anywhere}
td.problem{color:var(--ink-dim);max-width:24rem;overflow-wrap:anywhere}
pre{font-family:var(--mono);font-size:.82rem;line-height:1.5;background:var(--panel-2);border:1px solid var(--line);border-radius:10px;padding:.9rem 1rem;margin:.6rem 0 0;white-space:pre-wrap;overflow-wrap:anywhere;max-height:26rem;overflow:auto}
pre.err{border-color:rgba(255,123,123,.42);color:var(--bad)}
details.card{padding:0;overflow:hidden}
details.card>summary{cursor:pointer;padding:1rem 1.4rem;font-weight:650;color:var(--ink-dim);list-style:none}
details.card>summary::-webkit-details-marker{display:none}
details.card>summary:before{content:"\25B8  ";color:var(--ink-faint)}
details.card[open]>summary:before{content:"\25BE  "}
details.card>summary:hover{color:var(--ink)}
details.card>pre{margin:0;border:0;border-top:1px solid var(--line);border-radius:0;max-height:32rem}
details.card[open]>summary{border-bottom:1px solid var(--line)}
.table-wrap.compact th,.table-wrap.compact td{padding:.6rem .8rem}
.stat.warn{border-color:rgba(255,123,123,.42)}
.empty{padding:2.2rem 1.2rem;text-align:center;color:var(--ink-dim)}
.empty strong{display:block;color:var(--ink);font-size:1.02rem;margin-bottom:.25rem}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin:1.2rem 0}
@media(max-width:560px){.stats{grid-template-columns:1fr}}
.stat{display:block;padding:1.2rem 1.3rem;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--ink);text-decoration:none;box-shadow:var(--shadow);transition:border-color .15s,transform .15s}
.stat:hover{border-color:var(--line-2);transform:translateY(-1px)}
.stat .num{display:block;font-size:2.1rem;font-weight:750;letter-spacing:-.03em;line-height:1.1}
.stat .lbl{color:var(--ink-dim);font-size:.92rem}
.admin-head{display:flex;align-items:center;gap:1rem;margin:.2rem 0 .4rem}
.admin-head h1{margin:0}
.admin-head form{margin-left:auto}
.subnav{display:flex;gap:.4rem;flex-wrap:wrap;margin:1rem 0 1.4rem}
.subnav a{padding:.38rem .85rem;border-radius:999px;border:1px solid var(--line);color:var(--ink-dim);text-decoration:none;font-size:.88rem;font-weight:550}
.subnav a:hover{color:var(--ink);border-color:var(--line-2)}
.subnav a.active{color:var(--ink);border-color:var(--accent);background:var(--panel-2)}
@media (prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto!important}}
`

type pageData struct {
	Title string
	Admin bool
	Nav   string
	Body  template.HTML
}

var layoutTmpl = template.Must(template.New("layout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>{{.Title}}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%236aa8ff' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/%3E%3C/svg%3E">
<style>` + siteCSS + `</style>
</head><body>
<a class="skip" href="#main">Skip to content</a>
<div class="wrap">
<header class="site">
<a class="brand" href="/" aria-label="Home"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></a>
<nav class="main">
<a href="/apply"{{if eq .Nav "apply"}} class="active" aria-current="page"{{end}}>Apply</a>
<a href="/download"{{if eq .Nav "download"}} class="active" aria-current="page"{{end}}>Download</a>
{{if .Admin}}<a href="/admin"{{if eq .Nav "admin"}} class="active" aria-current="page"{{end}}>Admin</a>{{end}}
</nav>
</header>
<main id="main">{{.Body}}</main>
</div>
<script>
document.addEventListener('click',function(e){
var c=e.target.closest('[data-copy]');
if(c){e.preventDefault();var t=c.getAttribute('data-copy');
if(navigator.clipboard){navigator.clipboard.writeText(t).then(function(){var o=c.textContent;c.textContent='Copied';setTimeout(function(){c.textContent=o},1500)})}
else{window.prompt('Copy this link',t)}return}
var r=e.target.closest('[data-reveal]');
if(r){e.preventDefault();var i=document.getElementById(r.getAttribute('data-reveal'));
if(!i)return;var show=i.type==='password';i.type=show?'text':'password';r.textContent=show?'Hide':'Show'}
});
</script>
</body></html>`))

func (s *server) renderNav(w http.ResponseWriter, admin bool, nav, title, body string) {
	s.renderStatusNav(w, admin, nav, title, http.StatusOK, body)
}

func (s *server) renderStatusNav(w http.ResponseWriter, admin bool, nav, title string, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = layoutTmpl.Execute(w, pageData{Title: title, Admin: admin, Nav: nav, Body: template.HTML(body)})
}

func (s *server) render(w http.ResponseWriter, admin bool, title, body string) {
	s.renderNav(w, admin, "", title, body)
}

func (s *server) renderStatus(w http.ResponseWriter, admin bool, title string, status int, body string) {
	s.renderStatusNav(w, admin, "", title, status, body)
}

// ----------------------------------------------------------------- session ---

// sessionParts extracts the session identity from the request cookie. New
// sessions carry nonce|exp|sig; pre-rotation sessions carry exp|sig and are
// still honored until they expire.
func (s *server) sessionParts(r *http.Request) (nonce, exp string, ok bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", "", false
	}
	parts := strings.Split(string(raw), "|")
	switch len(parts) {
	case 3:
		return parts[0], parts[1], true
	case 2:
		return "", parts[0], true
	default:
		return "", "", false
	}
}

func sessionMAC(token, nonce, exp string) string {
	mac := hmac.New(sha256.New, []byte(token))
	if nonce != "" {
		mac.Write([]byte(nonce + "|" + exp))
	} else {
		mac.Write([]byte(exp))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// csrfToken is bound to the admin session, not just the server secret: a
// disclosed token works only with the session that minted it. The comparison
// in checkCSRF stays constant-time.
func (s *server) csrfToken(r *http.Request) string {
	nonce, exp, ok := s.sessionParts(r)
	if !ok {
		// No session: mint nothing usable. Callers only render forms for
		// authenticated sessions; this value will never verify.
		mac := hmac.New(sha256.New, []byte(s.token))
		mac.Write([]byte("csrf|no-session"))
		return hex.EncodeToString(mac.Sum(nil))
	}
	mac := hmac.New(sha256.New, []byte(s.token))
	if nonce != "" {
		mac.Write([]byte("csrf|" + nonce + "|" + exp))
	} else {
		mac.Write([]byte("csrf|" + exp))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *server) checkCSRF(r *http.Request) bool {
	given := r.FormValue("csrf")
	if given == "" {
		return false
	}
	return hmac.Equal([]byte(given), []byte(s.csrfToken(r)))
}

func (s *server) mintSession() *http.Cookie {
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		// Session must be unique per login; without randomness fail the
		// login rather than minting duplicate CSRF namespaces.
		return nil
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	exp := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	sig := sessionMAC(s.token, nonce, exp)
	val := base64.RawURLEncoding.EncodeToString([]byte(nonce + "|" + exp + "|" + sig))
	return &http.Cookie{
		Name: sessionCookie, Value: val, Path: "/admin",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(sessionTTL),
	}
}

func (s *server) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	var nonce, expStr, sig string
	switch len(parts) {
	case 3:
		nonce, expStr, sig = parts[0], parts[1], parts[2]
		if !validID.MatchString(nonce) && len(nonce) != 32 {
			// Nonce is 16 random bytes hex-encoded; reject garbage early.
			return false
		}
	case 2:
		expStr, sig = parts[0], parts[1]
	default:
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(sessionMAC(s.token, nonce, expStr)))
}

// bearerOK reports whether the request carries the machine API token.
func (s *server) bearerOK(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return false
	}
	given := strings.TrimPrefix(h, "Bearer ")
	return subtle.ConstantTimeCompare([]byte(given), []byte(s.token)) == 1
}

// requireAdmin allows the admin UI session.
func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.validSession(r) {
		w.Header().Set("Cache-Control", "no-store")
		return true
	}
	next := "/admin/login"
	if r.URL.Path != "/admin" && r.URL.Path != "/admin/" {
		next += "?next=" + r.URL.Path
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
	return false
}

func adminSubnav(active string) string {
	item := func(href, label, key string) string {
		class := ""
		if key == active {
			class = ` class="active"`
		}
		return fmt.Sprintf(`<a href="%s"%s>%s</a>`, href, class, label)
	}
	return `<div class="subnav">` +
		item("/admin", "Overview", "overview") +
		item("/admin/applications", "Applications", "applications") +
		item("/admin/users", "Logins", "users") +
		item("/admin/relay", "Relay", "relay") +
		item("/admin/split", "Split feed", "split") + `</div>`
}

// ---------------------------------------------------------------- landing ---

func (s *server) landing(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.render(w, s.validSession(r), "Home", `<section class="hero">
<h1>Enrollment</h1>
<p class="lede">Private DNS and tunnel for Windows and Linux.</p>
</section>
<div class="cta-grid">
<a class="cta" href="/apply">
<strong>Apply</strong>
<span>Name and reason. You get a status link.</span>
</a>
<a class="cta" href="/download">
<strong>Download</strong>
<span>Approved devices only.</span>
</a>
</div>`)
}

// ------------------------------------------------------------------ apply ---

func applyPage(name, why, osValue, errMsg string) string {
	alert := ""
	if errMsg != "" {
		alert = fmt.Sprintf(`<div class="alert error">%s</div>`, esc(errMsg))
	}
	sel := func(v string) string {
		if osValue == v {
			return " selected"
		}
		if osValue == "" && v == "windows" {
			return " selected"
		}
		return ""
	}
	return fmt.Sprintf(`<h1>Apply</h1>
%s
<form method="post" action="/apply" class="card">
<label for="name">Name</label>
<input id="name" name="name" maxlength="60" required autocomplete="name" value="%s">
<label for="why">Why you need access</label>
<textarea id="why" name="why" rows="4" maxlength="2000" required>%s</textarea>
<label for="os">OS</label>
<select id="os" name="os">
<option value="windows"%s>Windows</option>
<option value="linux"%s>Linux</option>
<option value="mac-arm64"%s>macOS (Apple Silicon)</option>
<option value="mac-amd64"%s>macOS (Intel)</option>
</select>
<input type="text" name="website" class="hp" tabindex="-1" autocomplete="off" aria-hidden="true">
<div class="actions"><button class="btn" type="submit">Submit</button></div>
</form>`, alert, esc(name), esc(why), sel("windows"), sel("linux"), sel("mac-arm64"), sel("mac-amd64"))
}

func (s *server) apply(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		s.renderNav(w, s.validSession(r), "apply", "Apply", applyPage("", "", "", ""))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allow(s.applys, clientIP(r), applyPerHour, time.Hour) {
		http.Error(w, "too many applications; try again later", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		s.renderNav(w, s.validSession(r), "apply", "Apply", applyPage("", "", "", "That submission was too large or unreadable."))
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	why := strings.TrimSpace(r.FormValue("why"))
	targetOS, targetArch := splitOSArch(r.FormValue("os"))
	osValue := r.FormValue("os")
	if osValue != "windows" && osValue != "linux" && osValue != "mac-arm64" && osValue != "mac-amd64" {
		osValue = "windows"
	}
	if r.FormValue("website") != "" {
		// Honeypot: pretend a bot submission succeeded, without storing.
		s.renderNav(w, false, "apply", "Applied", `<div class="alert ok">Application received.</div>`)
		return
	}
	if name == "" || why == "" || len(name) > 60 || len(why) > 2000 {
		s.renderNav(w, s.validSession(r), "apply", "Apply", applyPage(name, why, osValue, "Your name and a reason are both required."))
		return
	}
	var randBytes [16]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	claim := hex.EncodeToString(randBytes[:])
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d %s", time.Now().UnixNano(), claim)))
	id := hex.EncodeToString(sum[:])[:16]
	app := application{
		ID: id, Name: name, Why: why, OS: targetOS, Arch: targetArch, ClaimHash: hashClaim(claim),
		Created: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	tmp := filepath.Join(s.state, "applications", id+".json.new")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmp, filepath.Join(s.state, "applications", id+".json")); err != nil {
		_ = os.Remove(tmp)
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	link := "/status?app=" + id + "&key=" + claim
	s.renderNav(w, false, "apply", "Applied", fmt.Sprintf(`<h1>Application received</h1>
<div class="card">
<h2>Status link</h2>
<div class="linkbox"><code>%s</code><button type="button" class="btn ghost small" data-copy="%s">Copy</button></div>
<p class="muted">Bookmark this. Keep it private.</p>
<p><a class="btn" href="%s">Open status page</a></p>
</div>`, esc(link), esc(link), esc(link)))
}

// loadApplication returns the application only when the claim key verifies.
// Missing files and wrong keys are indistinguishable.
func (s *server) loadApplication(id, key string) (*application, bool) {
	if !validID.MatchString(id) || !validClaim.MatchString(key) {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(s.state, "applications", id+".json"))
	if err != nil {
		return nil, false
	}
	var app application
	if json.Unmarshal(data, &app) != nil {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(app.ClaimHash), []byte(hashClaim(key))) != 1 {
		return nil, false
	}
	return &app, true
}

func (s *server) saveApplication(app *application) error {
	data, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.state, "applications", app.ID+".json")
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ------------------------------------------------------------------ status ---

func timelineHTML(reviewed, ready bool) string {
	step := func(state, title, text string) string {
		return fmt.Sprintf(`<li class="%s"><span class="dot"></span><strong>%s</strong><p>%s</p></li>`, state, title, text)
	}
	applied := step("done", "Applied", "In the queue.")
	review := step("current", "Reviewed", "Waiting for review.")
	if reviewed {
		review = step("done", "Reviewed", "Approved.")
	}
	readyStep := step("", "Ready", "Set a password, then download.")
	if ready {
		readyStep = step("current", "Ready", "Set a password below.")
	}
	return `<ol class="timeline">` + applied + review + readyStep + `</ol>`
}

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	app, ok := s.loadApplication(r.URL.Query().Get("app"), r.URL.Query().Get("key"))
	if !ok {
		if !s.allow(s.fails, clientIP(r), authFailsMax, authWindow) {
			http.Error(w, "too many attempts; try again later", http.StatusTooManyRequests)
			return
		}
		http.NotFound(w, r)
		return
	}
	s.renderStatusPage(w, r, app, "", "")
}

func (s *server) renderStatusPage(w http.ResponseWriter, r *http.Request, app *application, notice, errMsg string) {
	users := s.loadUsers()
	var deviceHTML string
	if u, ok := users[app.LinkedUser]; ok {
		if stored, found := s.loadReport(u.Peer); found {
			label, class := effectiveStatus(stored.Report)
			latest := latestRelease(stored.Report.OS, stored.Report.Arch)
			state := "up to date"
			if latest != "" && stored.Report.Version != latest {
				state = "update available: " + latest
			}
			deviceHTML = fmt.Sprintf(`<div class="card tight"><p style="margin:0">Device: <span class="pill %s">%s</span> build <strong>%s</strong><br>
<span class="muted">Reported %s &middot; %s</span></p></div>`,
				class, esc(label), esc(stored.Report.Version), esc(timeAgo(stored.Received)), esc(state))
		} else {
			deviceHTML = `<div class="card tight"><p class="muted" style="margin:0">No install report from this device yet.</p></div>`
		}
	}
	_, userExists := users[app.LinkedUser]
	ready := app.Reviewed && app.LinkedUser != "" && userExists

	var b strings.Builder
	b.WriteString(`<h1>Status</h1>`)
	b.WriteString(`<div class="card tight"><p style="margin:0">Name: <strong>` +
		esc(app.Name) + `</strong><br><span class="muted">Submitted ` + esc(displayTime(app.Created)) +
		` &middot; ` + osLabel(app.OS, app.Arch) + `</span></p></div>`)
	b.WriteString(timelineHTML(app.Reviewed, ready))
	if deviceHTML != "" {
		b.WriteString(deviceHTML)
	}
	if notice != "" {
		fmt.Fprintf(&b, `<div class="alert ok">%s</div>`, esc(notice))
	}
	if errMsg != "" {
		fmt.Fprintf(&b, `<div class="alert error">%s</div>`, esc(errMsg))
	}

	switch {
	case !app.Reviewed:
		b.WriteString(`<div class="card"><p class="muted">Check back later.</p></div>`)
	case !ready:
		b.WriteString(`<div class="card"><p>Approved. Waiting for the installer.</p></div>`)
	default:
		u := users[app.LinkedUser]
		var creds strings.Builder
		if u.Password != "" {
			dl := "/download?username=" + url.QueryEscape(app.LinkedUser) +
				"&password=" + url.QueryEscape(u.Password)
			fmt.Fprintf(&creds, `<div class="card">
<h2>Login</h2>
<p>Username: <code>%s</code><br>Password: <code>%s</code></p>
<p><a class="btn" href="%s" target="_blank" rel="noopener">Download installer</a></p>
<p class="muted">One click. The tab stays open.</p>
</div>`, esc(app.LinkedUser), esc(u.Password), esc(dl))
		} else {
			creds.WriteString(`<div class="card">
<h2>Login</h2>
<p>Username: <code>` + esc(app.LinkedUser) + `</code></p>
<p class="muted">Ask the admin to reset the password.</p>
</div>`)
		}
		b.WriteString(creds.String())
	}
	s.renderNav(w, s.validSession(r), "", "Status", b.String())
}

func downloadPage(username, errMsg string) string {
	alert := ""
	if errMsg != "" {
		alert = fmt.Sprintf(`<div class="alert error">%s</div>`, esc(errMsg))
	}
	return fmt.Sprintf(`<h1>Download</h1>
%s
<form method="post" action="/download" class="card">
<label for="user">Username</label>
<input id="user" name="username" autocomplete="username" required value="%s">
<label for="pass">Password</label>
<div class="field-row">
<input id="pass" type="password" name="password" autocomplete="current-password" required>
<button type="button" class="btn ghost small" data-reveal="pass">Show</button>
</div>
<div class="actions"><button class="btn" type="submit">Download</button></div>
</form>`, alert, esc(username))
}

func (s *server) download(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// GET carries credentials in the query string (one-click links from the
	// applicant's status page); POST carries them in the form body. Both end
	// up in r.Form and share the checks below.
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable submission", http.StatusBadRequest)
		return
	}
	username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	password := r.FormValue("password")
	if r.Method == http.MethodGet && username == "" && password == "" {
		s.renderNav(w, s.validSession(r), "download", "Download", downloadPage("", ""))
		return
	}
	if !s.allow(s.fails, clientIP(r), authFailsMax, authWindow) {
		http.Error(w, "too many attempts; try again later", http.StatusTooManyRequests)
		return
	}

	users := s.loadUsers()
	u, known := users[username]
	hash := s.dummy
	if known {
		hash = []byte(u.Hash)
	}
	// Always run bcrypt so unknown users cost the same as known ones.
	ok := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil && known

	if !ok {
		s.renderStatusNav(w, s.validSession(r), "download", "Download", http.StatusUnauthorized,
			downloadPage(username, "Wrong username or password."))
		return
	}
	// Count the download. Best effort: a failed save must not block the file.
	s.usersMu.Lock()
	current := s.loadUsers()
	if fresh, ok := current[username]; ok {
		fresh.Downloads++
		fresh.LastDownload = time.Now().UTC().Format(time.RFC3339)
		current[username] = fresh
		u = fresh
		_ = s.saveUsers(current)
	}
	s.usersMu.Unlock()

	path := filepath.Join(s.state, "binaries", filepath.Base(u.Binary))
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "installer is not available; contact the administrator", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.Error(w, "installer is not available; contact the administrator", http.StatusServiceUnavailable)
		return
	}
	// Serve under the stored binary name: Windows, Linux and macOS builds all
	// have different naming, and the label alone cannot reconstruct it.
	filename := filepath.Base(u.Binary)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, filename, info.ModTime(), f)
}

func (s *server) loadUsers() map[string]user {
	data, err := os.ReadFile(filepath.Join(s.state, "users.json"))
	if err != nil {
		return map[string]user{}
	}
	var users map[string]user
	if err := json.Unmarshal(data, &users); err != nil {
		return map[string]user{}
	}
	return users
}

func (s *server) saveUsers(users map[string]user) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.state, "users.json.new")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.state, "users.json")); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s *server) loadApplications() []application {
	entries, _ := os.ReadDir(filepath.Join(s.state, "applications"))
	var apps []application
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.state, "applications", e.Name()))
		if err != nil {
			continue
		}
		var app application
		if json.Unmarshal(data, &app) == nil {
			apps = append(apps, app)
		}
	}
	return apps
}

// ------------------------------------------------------------ admin login ---

func loginPage(errMsg string) string {
	alert := ""
	if errMsg != "" {
		alert = fmt.Sprintf(`<div class="alert error">%s</div>`, esc(errMsg))
	}
	return fmt.Sprintf(`<h1>Admin</h1>
%s
<form method="post" action="/admin/login" class="card">
<label for="user">Username</label>
<input id="user" name="username" autocomplete="username" required>
<label for="pass">Password</label>
<div class="field-row">
<input id="pass" type="password" name="password" autocomplete="current-password" required>
<button type="button" class="btn ghost small" data-reveal="pass">Show</button>
</div>
<div class="actions"><button class="btn" type="submit">Log in</button></div>
</form>`, alert)
}

func (s *server) adminLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.validSession(r) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		s.render(w, false, "Admin login", loginPage(""))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allow(s.fails, clientIP(r), authFailsMax, authWindow) {
		http.Error(w, "too many attempts; try again later", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable submission", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	hash := s.dummy
	if subtle.ConstantTimeCompare([]byte(username), []byte(s.adminUser)) == 1 {
		hash = s.adminHash
	}
	ok := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil &&
		subtle.ConstantTimeCompare([]byte(username), []byte(s.adminUser)) == 1
	if !ok {
		s.render(w, false, "Admin login", loginPage("Wrong username or password."))
		return
	}
	cookie := s.mintSession()
	if cookie == nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	next := r.URL.Query().Get("next")
	if next == "" || !strings.HasPrefix(next, "/admin") {
		next = "/admin"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *server) adminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && s.validSession(r) && s.checkCSRF(r) {
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/admin", MaxAge: -1})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --------------------------------------------------------------- admin UI ---

func (s *server) adminDash(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" && r.URL.Path != "/admin/" {
		http.NotFound(w, r)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var pending int
	for _, a := range s.loadApplications() {
		if !a.Reviewed {
			pending++
		}
	}
	rows := s.deviceRows()
	var failed, parked, stale int
	for _, row := range rows {
		switch row.Label {
		case "failed":
			failed++
		case "parked":
			parked++
		case "stale":
			stale++
		}
	}

	body := fmt.Sprintf(`<div class="admin-head"><h1>Admin</h1>
<form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="%s">
<button class="btn ghost small" type="submit">Log out</button></form></div>
%s
<div class="stats">
<a class="stat" href="/admin/applications"><span class="num">%d</span><span class="lbl">pending applications</span></a>
<a class="stat%s" href="/admin/users"><span class="num">%d</span><span class="lbl">logins</span></a>
</div>
%s<h2>Devices</h2>
%s`,
		s.csrfToken(r), adminSubnav("overview"),
		pending,
		statClass(failed+parked+stale), len(rows),
		attentionAlert(failed, parked, stale),
		deviceTable(rows))
	s.renderNav(w, true, "admin", "Admin", body)
}

// statClass marks the logins card when something is wrong.
func statClass(bad int) string {
	if bad > 0 {
		return " warn"
	}
	return ""
}

// attentionAlert names the counts so the dashboard answers "is anything wrong"
// before any table is read.
func attentionAlert(failed, parked, stale int) string {
	if stale > 0 {
		// fall through to the generic builder below
	}
	var parts []string
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", failed))
	}
	if parked > 0 {
		parts = append(parts, fmt.Sprintf("%d parked", parked))
	}
	if stale > 0 {
		parts = append(parts, fmt.Sprintf("%d stale", stale))
	}
	if len(parts) == 0 {
		return `<div class="alert ok">Every device reported a working install.</div>`
	}
	return fmt.Sprintf(`<div class="alert error"><strong>%s.</strong> The table below is sorted worst first; open a login for its report.</div>`,
		strings.Join(parts, " and "))
}

func (s *server) adminApplications(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method == http.MethodPost {
		if !s.checkCSRF(r) {
			http.Error(w, "bad csrf token", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "unreadable", http.StatusBadRequest)
			return
		}
		id := r.FormValue("id")
		if !validID.MatchString(id) {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		action := r.FormValue("action")
		path := filepath.Join(s.state, "applications", id+".json")

		s.appsMu.Lock()
		app, ok := s.applicationByID(id)
		if !ok {
			s.appsMu.Unlock()
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		switch action {
		case "review", "retry":
			app.Reviewed = true
			app.ClaimedAt = ""
			app.ProvisionError = ""
		case "link":
			username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
			if _, ok := s.loadUsers()[username]; !ok {
				s.appsMu.Unlock()
				http.Error(w, "no such download login; publish it first", http.StatusBadRequest)
				return
			}
			app.LinkedUser = username
			app.Reviewed = true
			app.ClaimedAt = ""
			app.ProvisionError = ""
		case "delete":
			s.appsMu.Unlock()
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				http.Error(w, "could not delete", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/applications", http.StatusSeeOther)
			return
		default:
			s.appsMu.Unlock()
			http.Error(w, "bad action", http.StatusBadRequest)
			return
		}
		err := s.saveApplication(&app)
		s.appsMu.Unlock()
		if err != nil {
			http.Error(w, "could not save", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/applications", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var b strings.Builder
	b.WriteString(`<div class="admin-head"><h1>Applications</h1></div>`)
	b.WriteString(adminSubnav("applications"))
	apps := s.loadApplications()
	if len(apps) == 0 {
		b.WriteString(`<div class="table-wrap"><div class="empty"><strong>No applications.</strong></div></div>`)
	} else {
		b.WriteString(`<div class="table-wrap"><table><thead><tr><th>Name</th><th>Why</th><th>Status</th><th>Actions</th></tr></thead><tbody>`)
		for _, a := range apps {
			status := `<span class="pill new">new</span>`
			switch {
			case a.ProvisionError != "":
				status = fmt.Sprintf(`<span class="pill new">error</span><br><span class="muted">%s</span>`, esc(a.ProvisionError))
			case a.LinkedUser != "":
				status = fmt.Sprintf(`<span class="pill ok">linked: %s</span>`, esc(a.LinkedUser))
			case a.ClaimedAt != "":
				status = `<span class="pill">provisioning</span>`
			case a.Reviewed:
				status = `<span class="pill">approved</span>`
			}
			why := esc(a.Why)
			if why == "" {
				why = `<span class="muted">-</span>`
			}
			fmt.Fprintf(&b, `<tr><td><strong>%s</strong><br><span class="muted">%s, %s</span><br><code>%s</code></td><td class="why">%s</td><td>%s</td><td><div class="row-actions">`,
				esc(a.Name), esc(displayTime(a.Created)), osLabel(a.OS, a.Arch), esc(a.ID), why, status)
			if !a.Reviewed {
				fmt.Fprintf(&b, `<form method="post" action="/admin/applications">
<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">
<input type="hidden" name="action" value="review">
<button class="btn ghost small" type="submit">Approve</button></form>`, s.csrfToken(r), a.ID)
			}
			if a.ProvisionError != "" {
				fmt.Fprintf(&b, `<form method="post" action="/admin/applications">
<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">
<input type="hidden" name="action" value="retry">
<button class="btn ghost small" type="submit">Retry</button></form>`, s.csrfToken(r), a.ID)
			}
			fmt.Fprintf(&b, `<form method="post" action="/admin/applications">
<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">
<input type="hidden" name="action" value="link">
<input name="username" placeholder="login" size="8" value="%s" aria-label="Download login to link">
<button class="btn ghost small" type="submit">Link</button></form>
<form method="post" action="/admin/applications" onsubmit="return confirm('Delete this application?')">
<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s">
<input type="hidden" name="action" value="delete">
<button class="btn danger small" type="submit">Delete</button></form></div></td></tr>`,
				s.csrfToken(r), a.ID, esc(a.LinkedUser), s.csrfToken(r), a.ID)
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`<p class="muted">Approving queues it for the provisioner on hermes. It usually completes in under a minute.</p>`)
	s.renderNav(w, true, "admin", "Applications", b.String())
}

func (s *server) adminUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method == http.MethodPost {
		if !s.checkCSRF(r) {
			http.Error(w, "bad csrf token", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "unreadable", http.StatusBadRequest)
			return
		}
		username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
		if !validName.MatchString(username) {
			http.Error(w, "bad username", http.StatusBadRequest)
			return
		}
		action := r.FormValue("action")
		s.usersMu.Lock()
		users := s.loadUsers()
		u, ok := users[username]
		s.usersMu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		switch action {
		case "reset":
			password, err := randomPassword()
			if err != nil {
				http.Error(w, "could not generate password", http.StatusInternalServerError)
				return
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
			if err != nil {
				http.Error(w, "could not hash", http.StatusInternalServerError)
				return
			}
			s.usersMu.Lock()
			users = s.loadUsers()
			u, ok = users[username]
			if !ok {
				s.usersMu.Unlock()
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			u.Hash = string(hash)
			u.Password = password
			users[username] = u
			err = s.saveUsers(users)
			s.usersMu.Unlock()
			if err != nil {
				http.Error(w, "could not save", http.StatusInternalServerError)
				return
			}
			s.renderUsersPage(w, r, fmt.Sprintf(
				`New password for <strong>%s</strong>: <code>%s</code>`, esc(username), esc(password)))
			return

		case "revoke":
			// Remove the peer first. If that fails, keep the login so the
			// admin can retry rather than believing access was revoked.
			if u.Peer != "" {
				if err := revokePeer(u.Peer); err != nil {
					log.Printf("revoke %s: peer removal failed: %v", username, err)
					http.Error(w, "peer revocation failed: "+err.Error(), http.StatusInternalServerError)
					return
				}
			}
			s.usersMu.Lock()
			users = s.loadUsers()
			delete(users, username)
			err := s.saveUsers(users)
			s.usersMu.Unlock()
			if err != nil {
				log.Printf("revoke %s: user save failed: %v", username, err)
				http.Error(w, "could not save", http.StatusInternalServerError)
				return
			}
			log.Printf("revoke %s: done", username)
			// Remove the binary too: a revoked download must not linger.
			_ = os.Remove(filepath.Join(s.state, "binaries", filepath.Base(u.Binary)))
			http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
			return

		default:
			http.Error(w, "bad action", http.StatusBadRequest)
			return
		}
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.renderUsersPage(w, r, "")
}

func (s *server) renderUsersPage(w http.ResponseWriter, r *http.Request, noticeHTML string) {
	var b strings.Builder
	b.WriteString(`<div class="admin-head"><h1>Logins</h1></div>`)
	b.WriteString(adminSubnav("users"))
	if noticeHTML != "" {
		fmt.Fprintf(&b, `<div class="alert ok">%s</div>`, noticeHTML)
	}
	rows := s.deviceRows()
	if len(rows) == 0 {
		b.WriteString(`<div class="table-wrap"><div class="empty"><strong>No logins.</strong></div></div>`)
	} else {
		b.WriteString(`<div class="table-wrap compact"><table><thead><tr><th>Login</th><th>Device</th><th>Status</th><th>Access</th><th></th></tr></thead><tbody>`)
		for _, row := range rows {
			u := row.User

			device := esc(u.Label)
			if extra := strings.TrimSpace(osLabel(u.OS, u.Arch) + " &middot; " + esc(u.Binary)); extra != "" {
				device += `<span class="cell-sub">` + extra + `</span>`
			}
			device += fmt.Sprintf(`<span class="cell-sub">created %s</span>`, esc(displayTime(u.Created)))

			status := reportPill(row.Stored)
			if row.Stored != nil {
				if v := row.Stored.Report.Version; v != "" {
					status += fmt.Sprintf(`<span class="cell-sub">build %s</span>`, esc(v))
				}
				if p := problemText(row.Stored.Report); p != "" {
					status += fmt.Sprintf(`<span class="err-snip">%s</span>`, esc(p))
				}
				status += fmt.Sprintf(`<a class="cell-sub" href="/admin/reports?user=%s">open report</a>`, esc(row.Name))
			}

			downloads := `<span class="muted">never downloaded</span>`
			if u.Downloads > 0 {
				downloads = fmt.Sprintf(`%d downloads<span class="cell-sub">last %s</span>`,
					u.Downloads, esc(displayTime(u.LastDownload)))
			}
			password := `<span class="cell-sub">hashed only, reset for a new one</span>`
			if u.Password != "" {
				password = `<span class="cell-sub"><code>` + esc(u.Password) + `</code></span>`
			}

			fmt.Fprintf(&b, `<tr>
<td><code>%s</code></td>
<td>%s</td>
<td>%s</td>
<td>%s%s</td>
<td><div class="row-actions">
<form method="post" action="/admin/users">
<input type="hidden" name="csrf" value="%s"><input type="hidden" name="username" value="%s">
<input type="hidden" name="action" value="reset">
<button class="btn ghost small" type="submit">Reset password</button></form>
<form method="post" action="/admin/users" onsubmit="return confirm('Revoke this login, delete the installer, and remove the WireGuard peer?')">
<input type="hidden" name="csrf" value="%s"><input type="hidden" name="username" value="%s">
<input type="hidden" name="action" value="revoke">
<button class="btn danger small" type="submit">Revoke</button></form></div></td></tr>`,
				esc(row.Name), device, status, downloads, password,
				s.csrfToken(r), esc(row.Name), s.csrfToken(r), esc(row.Name))
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`<p class="muted">Worst first. Passwords are stored as bcrypt hashes, so they
cannot be read back; reset shows a new one once. Revoking removes the login,
installer, and WireGuard peer.</p>`)
	s.renderNav(w, true, "admin", "Logins", b.String())
}

// adminAddUser registers a download login: bearer token (publish-device.sh)
// or an admin UI session with a valid CSRF token. Body is form-encoded:
// username, password, label, binary.
func (s *server) adminAddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	authed := s.bearerOK(r)
	if !authed && s.validSession(r) && s.checkCSRF(r) {
		authed = true
	}
	if !authed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	password := r.FormValue("password")
	label := strings.TrimSpace(r.FormValue("label"))
	binary := filepath.Base(strings.TrimSpace(r.FormValue("binary")))
	peer := strings.TrimSpace(r.FormValue("peer"))
	targetOS := r.FormValue("os")
	targetArch := r.FormValue("arch")
	if targetOS != "windows" && targetOS != "linux" && targetOS != "darwin" {
		targetOS = "windows"
	}
	if targetArch != "amd64" && targetArch != "arm64" {
		if targetOS == "darwin" {
			targetArch = "arm64"
		} else {
			targetArch = "amd64"
		}
	}
	if !validName.MatchString(username) || len(username) > maxUsernameLen ||
		len(password) < 12 || len(password) > 200 || label == "" || len(label) > 60 {
		http.Error(w, "bad fields (username a-z0-9._-, password at least 12 chars, label required)", http.StatusBadRequest)
		return
	}
	if peer != "" && !validWireGuardKey(peer) {
		http.Error(w, "bad peer key", http.StatusBadRequest)
		return
	}
	badName := true
	switch targetOS {
	case "windows":
		badName = !strings.HasSuffix(binary, ".exe")
	case "linux":
		badName = strings.HasSuffix(binary, ".exe") || strings.Contains(binary, "-darwin-")
	case "darwin":
		badName = !strings.Contains(binary, "-darwin-"+targetArch)
	}
	if badName {
		http.Error(w, "bad binary name for "+targetOS+"/"+targetArch, http.StatusBadRequest)
		return
	}
	if info, err := os.Stat(filepath.Join(s.state, "binaries", binary)); err != nil || info.IsDir() {
		http.Error(w, "binary is not on the server", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		http.Error(w, "could not hash", http.StatusInternalServerError)
		return
	}

	// Never overwrite: replacing the row would orphan the previous WireGuard
	// peer (full tunnel access, linked from no admin screen) and reset the
	// download audit trail. The operator revokes first, which removes the
	// peer, then re-publishes.
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	users := s.loadUsers()
	if _, exists := users[username]; exists {
		http.Error(w, "username exists; revoke it in the admin UI first, then re-publish", http.StatusConflict)
		return
	}
	users[username] = user{
		Hash: string(hash), Password: password, Binary: binary, Label: label,
		OS: targetOS, Arch: targetArch, Peer: peer,
		Created: time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.saveUsers(users); err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "registered")
}

// adminLink attaches a download login to an application and marks it
// reviewed, so the applicant's status link offers password setup. Same auth
// as adminAddUser. Body: id, username.
func (s *server) adminLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	authed := s.bearerOK(r)
	if !authed && s.validSession(r) && s.checkCSRF(r) {
		authed = true
	}
	if !authed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := r.FormValue("id")
	username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	if !validID.MatchString(id) || !validName.MatchString(username) {
		http.Error(w, "bad fields", http.StatusBadRequest)
		return
	}
	if _, ok := s.loadUsers()[username]; !ok {
		http.Error(w, "no such download login", http.StatusBadRequest)
		return
	}
	s.appsMu.Lock()
	defer s.appsMu.Unlock()
	app, ok := s.applicationByID(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	app.LinkedUser = username
	app.Reviewed = true
	app.ClaimedAt = ""
	app.ProvisionError = ""
	if err := s.saveApplication(&app); err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "linked")
}
