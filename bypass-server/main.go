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
	// DeviceID, EnrollToken and ProvisionedAt are set when approval prepares
	// the installer. The token is single-use and expires.
	DeviceID      string `json:"device_id,omitempty"`
	EnrollToken   string `json:"enroll_token,omitempty"`
	ProvisionedAt string `json:"provisioned_at,omitempty"`
	// SetupDownloads counts served setup archives. Approval hands out the
	// generic installer through this archive, not through a per-login file, so
	// the Logins page cannot answer "did they get it?".
	SetupDownloads  int    `json:"setup_downloads,omitempty"`
	SetupDownloaded string `json:"setup_downloaded,omitempty"`
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
	devicesMu sync.Mutex
	fails     map[string][]time.Time
	applys    map[string][]time.Time
	reports   map[string][]time.Time
	splits    map[string][]time.Time
	enrolls   map[string][]time.Time
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
		enrolls: map[string][]time.Time{},
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/assets/varela-round.ttf", s.fontAsset)
	s.mux.HandleFunc("/", s.landing)
	s.mux.HandleFunc("/apply", s.apply)
	s.mux.HandleFunc("/status", s.status)
	s.mux.HandleFunc("/setup/", s.setupArchive)
	s.mux.HandleFunc("/download", s.download)
	s.mux.HandleFunc("/admin/login", s.adminLogin)
	s.mux.HandleFunc("/admin/logout", s.adminLogout)
	s.mux.HandleFunc("/admin", s.adminDash)
	s.mux.HandleFunc("/admin/applications", s.adminApplications)
	s.mux.HandleFunc("/admin/applications/", s.adminApplicationDetail)
	s.mux.HandleFunc("/admin/users", s.adminUsers)
	s.mux.HandleFunc("/admin/users/", s.adminUserDetail)
	s.mux.HandleFunc("/admin/api/users", s.adminAddUser)
	s.mux.HandleFunc("/admin/api/link", s.adminLink)
	s.mux.HandleFunc("/api/report", s.apiReport)
	s.mux.HandleFunc("/api/support", s.apiSupport)
	s.mux.HandleFunc("/api/heartbeat", s.apiHeartbeat)
	s.mux.HandleFunc("/api/blocked-report", s.apiBlockedReport)
	s.mux.HandleFunc("/api/seed", s.apiSeed)
	s.mux.HandleFunc("/api/peers", s.apiPeers)
	s.mux.HandleFunc("/api/enroll", s.apiEnroll)
	s.mux.HandleFunc("/admin/reports", s.adminReports)
	s.mux.HandleFunc("/admin/split", s.adminSplit)
	s.mux.HandleFunc("/admin/devices", s.adminDevices)
	s.mux.HandleFunc("/admin/devices/", s.adminDeviceDetail)
	s.mux.HandleFunc("/admin/exits", s.adminExits)
	s.mux.HandleFunc("/admin/relay", s.adminRelay)
	s.mux.HandleFunc("/admin/relay/", s.adminRelayDetail)
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

const siteCSS = `@font-face{font-family:"Varela Round";src:url("/assets/varela-round.ttf") format("truetype");font-display:swap;font-weight:400}
:root{
color-scheme:dark;
--bg:#0c0c0c;--surface:#1a1a1a;--surface-2:#212121;--overlay:#d8d8d8;
--fg:#f0f0f0;--dim:#c2bcb2;--faint:#9b958d;
--line:rgba(232,232,232,.10);--line-2:rgba(232,232,232,.22);
--accent:#eab672;--accent-ink:#0c0c0c;--accent-soft:rgba(234,182,114,.14);
--ok:#a7cf86;--warn:#e3a85c;--bad:#d98b6a;--info:#a8c0b4;
--xs:4px;--sm:8px;--md:12px;--lg:16px;--xl:20px;
--r:8px;--r-sm:6px;--r-xs:4px;--pill:999px;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--shadow:0 14px 34px -22px rgba(0,0,0,.95);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font:15px/1.7 "Varela Round",ui-rounded,system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--fg);background:var(--bg);-webkit-font-smoothing:antialiased;min-height:100vh}
.wrap{max-width:64rem;margin:0 auto;padding:0 var(--xl) 64px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:var(--r-xs)}
.skip{position:absolute;left:-9999px;top:0;background:var(--surface);padding:var(--sm) var(--md);border-radius:0 0 var(--r) 0;z-index:9}
.skip:focus{left:0}
header.site{display:flex;align-items:center;gap:var(--md);padding:var(--lg) 0 var(--md);margin-bottom:var(--xl);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:var(--sm);font-weight:700;color:var(--fg);letter-spacing:.01em;font-size:15px}
.brand svg{width:22px;height:22px;color:var(--accent);flex:none}
.brand span{color:var(--dim);font-weight:400;font-size:12px;margin-left:var(--xs)}
nav.main{margin-left:auto;display:flex;gap:var(--xs);align-items:center;flex-wrap:wrap}
nav.main a{padding:var(--xs) var(--md);border-radius:var(--r-sm);color:var(--dim);font-size:13px}
nav.main a:hover{color:var(--fg);background:var(--surface);text-decoration:none}
nav.main a.active{color:var(--fg);background:var(--surface);box-shadow:inset 0 0 0 1px var(--line-2)}
.hero{padding:32px 0 var(--lg)}
.hero h1{font-size:clamp(28px,4vw,40px);line-height:1.15;letter-spacing:-.01em;margin:0 0 var(--md);max-width:24ch}
.lede{font-size:16px;color:var(--dim);max-width:56ch;margin:0}
h1{font-size:26px;line-height:1.2;margin:var(--xs) 0 var(--md);font-weight:700}
h2{font-size:16px;margin:0 0 var(--sm);font-weight:700;color:var(--fg)}
h3{font-size:14px;margin:var(--md) 0 var(--xs)}
p{margin:var(--md) 0;max-width:68ch}
small,.muted{color:var(--faint);font-size:12.5px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:var(--lg);margin:var(--md) 0;box-shadow:var(--shadow)}
.card.tight{padding:var(--md)}
.card p:last-child{margin-bottom:0}
.card h2:first-child,.card h3:first-child{margin-top:0}
.cta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:var(--md);margin:var(--xl) 0}
@media(max-width:660px){.cta-grid{grid-template-columns:1fr}.hero{padding-top:var(--lg)}}
.cta{display:block;padding:var(--lg);border:1px solid var(--line);border-radius:var(--r);background:var(--surface);color:var(--fg);box-shadow:var(--shadow)}
.cta:hover{border-color:var(--line-2);background:var(--surface-2);text-decoration:none}
.cta strong{display:block;font-size:15px;margin-bottom:var(--xs)}
.cta span:last-child{display:block;color:var(--dim);font-size:13px}
label{display:block;font-weight:700;font-size:12px;letter-spacing:.02em;color:var(--dim);margin:var(--lg) 0 var(--xs)}
input,textarea,select{width:100%;padding:var(--md) var(--lg);border-radius:var(--r-sm);border:1px solid var(--line-2);background:var(--surface-2);color:var(--fg);font:inherit;font-size:14px}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
textarea{resize:vertical;min-height:104px}
.hint{display:block;color:var(--faint);font-size:12px;margin-top:var(--xs)}
.hp{position:absolute;left:-9999px;width:1px;height:1px;opacity:0}
.field-row{display:flex;gap:var(--sm);align-items:stretch}
.field-row input{flex:1 1 auto;min-width:0}
.actions{display:flex;gap:var(--sm);align-items:center;margin-top:var(--lg);flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:var(--xs);background:var(--accent);color:var(--accent-ink);border:1px solid transparent;border-radius:var(--r);padding:var(--sm) var(--lg);font:inherit;font-weight:700;font-size:14px;cursor:pointer;text-decoration:none}
.btn:hover{filter:brightness(1.06);text-decoration:none}
.btn.ghost{background:transparent;color:var(--dim);border-color:var(--line-2)}
.btn.ghost:hover{color:var(--fg);border-color:var(--accent);filter:none}
.btn.danger{background:transparent;color:var(--bad);border-color:rgba(217,139,106,.45)}
.btn.danger:hover{background:rgba(217,139,106,.10);filter:none}
.btn.small{padding:var(--xs) var(--sm);font-size:12px;border-radius:var(--r-sm)}
.alert{border-radius:var(--r);padding:var(--sm) var(--md);margin:var(--md) 0;border:1px solid;font-size:13px}
.alert.error,.banner.off{background:rgba(217,139,106,.10);border-color:rgba(217,139,106,.40);color:var(--bad)}
.alert.ok,.banner.ok{background:rgba(167,207,134,.10);border-color:rgba(167,207,134,.38);color:var(--ok)}
.alert.info,.banner.info{background:var(--accent-soft);border-color:rgba(234,182,114,.36);color:var(--accent)}
.banner{border-radius:var(--r);padding:var(--md);margin:var(--md) 0;border:1px solid;font-size:13px}
.warn{color:var(--warn)}
.timeline{list-style:none;margin:var(--lg) 0 0;padding:0}
.timeline li{position:relative;padding:0 0 var(--xl) 32px}
.timeline li:before{content:"";position:absolute;left:7px;top:20px;bottom:0;width:1px;background:var(--line-2)}
.timeline li:last-child{padding-bottom:0}
.timeline li:last-child:before{display:none}
.timeline .dot{position:absolute;left:0;top:3px;width:15px;height:15px;border-radius:50%;border:2px solid var(--line-2);background:var(--surface)}
.timeline li.done .dot{background:var(--ok);border-color:var(--ok)}
.timeline li.current .dot{border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-soft)}
.timeline strong{display:block;font-size:14px}
.timeline p{margin:var(--xs) 0 0;color:var(--dim);font-size:13px}
.linkbox{display:flex;gap:var(--sm);align-items:stretch;margin:var(--md) 0;flex-wrap:wrap}
.linkbox code{flex:1 1 18rem;min-width:0;overflow-wrap:anywhere;background:var(--surface-2);border:1px solid var(--line-2);border-radius:var(--r-sm);padding:var(--sm) var(--md);font-family:var(--mono);font-size:12px;line-height:1.5}
code{font-family:var(--mono);font-size:.92em;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-xs);padding:1px 5px}
pre{font-family:var(--mono);font-size:12px;line-height:1.55;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-sm);padding:var(--md);margin:var(--sm) 0 0;white-space:pre-wrap;overflow-wrap:anywhere;max-height:26rem;overflow:auto}
pre.err{border-color:rgba(217,139,106,.42);color:var(--bad)}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r);background:var(--surface);box-shadow:var(--shadow);margin:var(--md) 0}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:10px var(--md);border-bottom:1px solid var(--line);vertical-align:top;line-height:1.5}
th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);background:var(--surface-2);font-weight:700;white-space:nowrap}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(232,232,232,.025)}
td form{display:inline-flex;gap:var(--xs);align-items:center;margin:0}
td input{padding:var(--xs) var(--sm);font-size:12px;border-radius:var(--r-xs);width:9rem}
.row-actions{display:flex;gap:var(--xs);flex-wrap:wrap;align-items:center}
.why{max-width:26rem;overflow-wrap:anywhere;color:var(--dim)}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:1px 9px;border-radius:var(--pill);background:var(--surface-2);border:1px solid var(--line-2);color:var(--dim);white-space:nowrap}
.pill.new{background:var(--accent-soft);border-color:rgba(234,182,114,.45);color:var(--accent)}
.pill.ok{background:rgba(167,207,134,.12);border-color:rgba(167,207,134,.42);color:var(--ok)}
.pill.bad{background:rgba(217,139,106,.12);border-color:rgba(217,139,106,.42);color:var(--bad)}
.pill.skip{background:var(--surface-2);border-color:var(--line);color:var(--faint)}
.report-head{display:flex;flex-wrap:wrap;gap:var(--sm) var(--md);align-items:center}
.report-meta{color:var(--dim);font-size:12px}
.cell-sub{display:block;color:var(--dim);font-size:12px;margin-top:2px}
a.cell-sub{color:var(--accent)}
.err-snip{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;color:var(--bad);font-size:12px;overflow-wrap:anywhere}
td.problem{color:var(--dim);max-width:24rem;overflow-wrap:anywhere}
details.card{padding:0;overflow:hidden}
details.card>summary{cursor:pointer;padding:var(--md) var(--lg);font-weight:700;font-size:13px;color:var(--dim);list-style:none}
details.card>summary::-webkit-details-marker{display:none}
details.card>summary:before{content:"B8  ";color:var(--faint)}
details.card[open]>summary:before{content:"BE  "}
details.card>summary:hover{color:var(--fg)}
details.card>pre{margin:0;border:0;border-top:1px solid var(--line);border-radius:0;max-height:32rem}
details.card[open]>summary{border-bottom:1px solid var(--line)}
.card-body{padding:var(--md) var(--lg)}
.table-wrap.compact th,.table-wrap.compact td{padding:var(--sm) var(--md)}
.empty{padding:32px var(--md);text-align:center;color:var(--dim)}
.empty strong{display:block;color:var(--fg);font-size:14px;margin-bottom:var(--xs)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:var(--md);margin:var(--md) 0 var(--xl)}
.stats.compact{gap:var(--sm);margin:0 0 var(--md)}
.stats.compact .stat{padding:var(--sm) var(--md)}
.stats.compact .num{font-size:20px}
.why-clamp{display:-webkit-box;-webkit-line-clamp:1;-webkit-box-orient:vertical;overflow:hidden;max-width:38ch;white-space:normal}
td.why{padding-top:11px}
@media(max-width:760px){.stats{grid-template-columns:1fr 1fr}}
@media(max-width:420px){.stats{grid-template-columns:1fr}}
.stat{display:block;padding:var(--lg);border:1px solid var(--line);border-radius:var(--r);background:var(--surface);color:var(--fg);box-shadow:var(--shadow)}
a.stat:hover{border-color:var(--line-2);background:var(--surface-2);text-decoration:none}
.stat .num{display:block;font-size:28px;font-weight:700;line-height:1.1}
.stat .lbl{color:var(--dim);font-size:12px}
.stat.warn{border-color:rgba(217,139,106,.42)}
.admin-head{display:flex;align-items:center;gap:var(--md);margin:var(--xs) 0 var(--xs)}
.admin-head h1{margin:0}
.admin-head form{margin-left:auto}
.subnav{display:flex;gap:var(--xs);flex-wrap:wrap;margin:var(--md) 0 var(--xl)}
.subnav a{padding:5px var(--md);border-radius:var(--pill);border:1px solid var(--line);color:var(--dim);font-size:12px;font-weight:700}
.subnav a:hover{color:var(--fg);border-color:var(--line-2);text-decoration:none}
.subnav a.active{color:var(--fg);border-color:var(--accent);background:var(--surface)}
.app-row{display:flex;gap:var(--md);align-items:flex-start;padding:var(--md);border-bottom:1px solid var(--line)}
.app-row:last-child{border-bottom:none}
.app-main{flex:1 1 auto;min-width:0}
.app-title{display:flex;gap:var(--sm);align-items:center;flex-wrap:wrap}
.app-title strong{font-size:14px}
.app-meta{color:var(--dim);font-size:12.5px;margin-top:3px}
.app-why{color:var(--dim);font-size:14px;margin-top:var(--sm);overflow-wrap:anywhere;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;max-width:70ch}
.app-actions{display:flex;gap:var(--xs);flex-wrap:wrap;justify-content:flex-end;min-width:9rem}
.stat-inline{display:flex;gap:var(--md);flex-wrap:wrap;color:var(--dim);font-size:12px;margin:var(--sm) 0 0}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:var(--xs) var(--md);font-size:13px;margin:var(--sm) 0}
.kv dt{color:var(--faint);font-size:12px}
.kv dd{margin:0;overflow-wrap:anywhere}
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
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23eab672' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/%3E%3C/svg%3E">
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
		item("/admin/users", "Download logins", "users") +
		item("/admin/relay", "Relay", "relay") +
		item("/admin/devices", "Devices", "devices") +
		item("/admin/split", "Split feed", "split") +
		item("/admin/exits", "Exits", "exits") + `</div>`
}

// ---------------------------------------------------------------- landing ---

func (s *server) landing(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.render(w, s.validSession(r), "Home", `<section class="hero">
<h1>When your network blocks it.</h1>
<p class="lede">A tunnel and private DNS for filtered networks.</p>
</section>
<div class="cta-grid">
<a class="cta" href="/apply"><strong>Apply</strong><span>Two fields. Then a status page.</span></a>
<a class="cta" href="/download"><strong>Download</strong><span>Approved devices.</span></a>
<a class="cta" href="/status"><strong>Already applied?</strong><span>Open your status page.</span></a>
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
<label for="why">What do you need it for?</label>
<textarea id="why" name="why" rows="3" maxlength="2000" placeholder="One or two sentences." required>%s</textarea>
<label for="os">Device</label>
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
	s.rememberApplication(w, r, &app, claim)
	s.renderNav(w, false, "apply", "Applied", fmt.Sprintf(`<h1>Application received</h1>
<div class="card">
<h2>You can close this page</h2>
<p>This browser remembers it. Use the link below for another device.</p>
<div class="linkbox"><code>%s</code><button type="button" class="btn ghost small" data-copy="%s">Copy</button></div>
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
	applied := step("done", "Applied", "Received and in the queue.")
	review := step("current", "Reviewed", "Waiting for approval.")
	if reviewed {
		review = step("done", "Reviewed", "Approved.")
	}
	installer := step("", "Installer", "Prepared after approval.")
	if ready {
		installer = step("current", "Installer ready", "Download it below.")
	}
	return `<ol class="timeline">` + applied + review + installer + `</ol>`
}

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	app, ok := s.applicationForRequest(r)
	if !ok {
		// No link and no cookie: this is a returning applicant without their
		// link, not an error. Only a wrong id or key stays a 404 so the page
		// cannot be used to probe applications.
		if r.URL.Query().Get("app") == "" && r.URL.Query().Get("key") == "" {
			s.renderNav(w, s.validSession(r), "", "Status", `<div class="admin-head"><h1>Status</h1></div>
<div class="card"><h2>No application on this browser</h2>
<p>Open the link you saved, or <a href="/apply">apply</a>.</p></div>`)
			return
		}
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
	setupReady := app.Reviewed && app.DeviceID != "" && app.EnrollToken != ""
	setupHref := "/setup/" + app.ID + ".zip"
	if key := r.URL.Query().Get("key"); key != "" {
		setupHref += "?key=" + url.QueryEscape(key)
	}
	users := s.loadUsers()
	var legacyHTML string
	if u, ok := users[app.LinkedUser]; ok {
		if stored, found := s.loadReport(u.Peer); found {
			label, class := effectiveStatus(stored.Report)
			latest := latestRelease(stored.Report.OS, stored.Report.Arch)
			state := "up to date"
			if latest != "" && stored.Report.Version != latest {
				state = "update available: " + latest
			}
			legacyHTML = fmt.Sprintf(`<div class="card tight"><p style="margin:0">Device: <span class="pill %s">%s</span> build <strong>%s</strong><br><span class="muted">Reported %s &middot; %s</span></p></div>`,
				class, esc(label), esc(stored.Report.Version), esc(timeAgo(stored.Received)), esc(state))
		}
	}

	var b strings.Builder
	b.WriteString(`<div class="admin-head"><h1>Your application</h1></div>`)
	b.WriteString(`<div class="card tight"><div class="app-title"><strong>` + esc(app.Name) + `</strong><span class="pill">` + esc(osLabel(app.OS, app.Arch)) + `</span></div>
<div class="app-meta">Submitted ` + esc(displayTime(app.Created)) + ` &middot; reference <code>` + esc(app.ID) + `</code></div></div>`)
	b.WriteString(timelineHTML(app.Reviewed, setupReady))
	if notice != "" {
		fmt.Fprintf(&b, `<div class="alert ok">%s</div>`, esc(notice))
	}
	if errMsg != "" {
		fmt.Fprintf(&b, `<div class="alert error">%s</div>`, esc(errMsg))
	}
	if legacyHTML != "" {
		b.WriteString(legacyHTML)
	}

	switch {
	case !app.Reviewed:
		b.WriteString(`<div class="card"><h2>Under review</h2><p>Check back here. This browser remembers your application.</p></div>`)
	case !setupReady:
		b.WriteString(`<div class="card"><h2>Preparing your installer</h2><p>Approved. Refresh in a few minutes.</p></div>`)
	default:
		fmt.Fprintf(&b, `<div class="card">
<h2>Installer ready</h2>
<p>Download, extract, then right-click <code>egress.exe</code> and <strong>Run as administrator</strong>. Keep <code>enroll.txt</code> beside it.</p>
<p><a class="btn" href="%s">Download setup (.zip)</a></p>
<details><summary>Manual setup and token</summary>
<p>Run this in an administrator PowerShell with <code>enroll.txt</code> beside the exe:</p>
<pre>.\\egress.exe install --enroll-token %s</pre>
<p>Token: <code>%s</code></p>
</details>
<p class="muted">The token works once.</p>
</div>`, esc(setupHref), esc(app.EnrollToken), esc(app.EnrollToken))
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
	// Trim the password too: a pasted value routinely carries a trailing
	// newline, and generated passwords never contain whitespace, so a stray
	// one is always a paste artefact rather than part of the secret.
	password := strings.TrimSpace(r.FormValue("password"))
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
		// Caddy discards access logs for this host, so a rejected attempt is
		// only visible here. "He downloaded it" and "the password never
		// worked" are otherwise indistinguishable.
		log.Printf("download: rejected %q from %s", username, clientIP(r))
		s.renderStatusNav(w, s.validSession(r), "download", "Download", http.StatusUnauthorized,
			downloadPage(username, "Wrong username or password."))
		return
	}

	path := filepath.Join(s.state, "binaries", filepath.Base(u.Binary))
	f, err := os.Open(path)
	if err != nil {
		log.Printf("download: %q from %s has no installer at %s", username, clientIP(r), path)
		http.Error(w, "installer is not available; contact the administrator", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		log.Printf("download: %q from %s has an unusable installer at %s", username, clientIP(r), path)
		http.Error(w, "installer is not available; contact the administrator", http.StatusServiceUnavailable)
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
	log.Printf("download: %q from %s sent %s (%d bytes)", username, clientIP(r), filepath.Base(u.Binary), info.Size())
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

// recentApplicationsHTML is the dashboard's short queue view.
func recentApplicationsHTML(apps []application, deviceStatus map[string]string) string {
	if len(apps) == 0 {
		return `<div class="table-wrap"><div class="empty"><strong>No applications yet.</strong></div></div>`
	}
	var b strings.Builder
	b.WriteString(`<div class="card" style="padding:0">`)
	for i, a := range apps {
		if i >= 6 {
			break
		}
		chip, class := "waiting", "new"
		switch {
		case a.ProvisionError != "":
			chip, class = "failed", "bad"
		case a.DeviceID != "" && deviceStatus[a.DeviceID] == "bound":
			chip, class = "installed", "ok"
		case a.DeviceID != "":
			chip, class = "installer ready", "ok"
		case a.Reviewed:
			chip, class = "approved", ""
		}
		fmt.Fprintf(&b, `<div class="app-row"><div class="app-main"><div class="app-title"><strong>%s</strong><span class="pill %s">%s</span><span class="pill">%s</span></div><div class="app-meta">%s</div></div><div class="app-actions"><a class="btn ghost small" href="/admin/applications">Open</a></div></div>`,
			esc(a.Name), class, chip, esc(osLabel(a.OS, a.Arch)), esc(displayTime(a.Created)))
	}
	b.WriteString(`</div>`)
	return b.String()
}

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

	fl := s.loadFleet()
	bound, invited := fl.boundDevices()
	_, ready, _, _ := fl.counts()
	body := fmt.Sprintf(`<div class="admin-head"><h1>Overview</h1>
<form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="%s">
<button class="btn ghost small" type="submit">Log out</button></form></div>
%s
<div class="stats">
<a class="stat" href="/admin/applications"><span class="num">%d</span><span class="lbl">waiting for approval</span></a>
<a class="stat" href="/admin/applications"><span class="num">%d</span><span class="lbl">installers ready</span></a>
<a class="stat" href="/admin/devices"><span class="num">%d</span><span class="lbl">installed devices</span></a>
<a class="stat" href="/admin/devices"><span class="num">%d</span><span class="lbl">open invites</span></a>
</div>
%s<h2>Recent applications</h2>
%s
<h2>Devices</h2>
%s`,
		s.csrfToken(r), adminSubnav("overview"),
		pending, ready, bound, invited,
		attentionAlert(failed, parked, stale),
		recentApplicationsHTML(fl.apps, fl.deviceStatusMap()),
		s.fleetTableHTML(fl))
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
		case "approve", "retry":
			app.Reviewed = true
			app.ClaimedAt = ""
			app.ProvisionError = ""
			if err := s.provisionApplication(&app); err != nil {
				app.ProvisionError = err.Error()
			}
		case "review":
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
	f := s.loadFleet()
	apps := f.apps
	pending, ready, installed, errored := f.counts()
	b.WriteString(`<div class="admin-head"><h1>Applications</h1></div>`)
	b.WriteString(adminSubnav("applications"))
	b.WriteString(`<div class="stats compact">`)
	fmt.Fprintf(&b, `<a class="stat" href="/admin/applications"><span class="num">%d</span><span class="lbl">waiting</span></a>`, pending)
	fmt.Fprintf(&b, `<a class="stat" href="/admin/applications"><span class="num">%d</span><span class="lbl">ready</span></a>`, ready)
	fmt.Fprintf(&b, `<a class="stat" href="/admin/devices"><span class="num">%d</span><span class="lbl">installed</span></a>`, installed)
	fmt.Fprintf(&b, `<a class="stat%s" href="/admin/applications"><span class="num">%d</span><span class="lbl">attention</span></a>`, statClass(errored), errored)
	b.WriteString(`</div>`)
	if len(apps) == 0 {
		b.WriteString(`<div class="table-wrap"><div class="empty"><strong>No applications yet.</strong>Share the apply page.</div></div>`)
	} else {
		b.WriteString(`<div class="table-wrap"><table><thead><tr><th>Applicant</th><th>Status</th><th>Report</th><th>Reason</th><th>Installer</th><th></th></tr></thead><tbody>`)
		for _, a := range apps {
			chip, chipClass := f.appState(a)
			installer := `<span class="muted">&mdash;</span>`
			switch {
			case a.ProvisionError != "":
				installer = fmt.Sprintf(`<span class="err-snip">%s</span>`, esc(a.ProvisionError))
			case chip == "installed":
				installer = `<span class="muted">installed</span>`
			case a.DeviceID != "":
				installer = fmt.Sprintf(`<code>%s</code> <button type="button" class="btn ghost small" data-copy="%s">Copy token</button>`, esc(a.DeviceID), esc(a.EnrollToken))
				if a.SetupDownloads > 0 {
					installer += fmt.Sprintf(`<span class="cell-sub">fetched %d&times; &middot; %s</span>`, a.SetupDownloads, esc(displayTime(a.SetupDownloaded)))
				} else {
					installer += `<span class="cell-sub">not fetched yet</span>`
				}
			}
			report := `<span class="muted">&mdash;</span>`
			if d, ok := f.appDevice(a); ok {
				report = s.deviceReportCell(d.PubKey)
			}
			why := a.Why
			fmt.Fprintf(&b, `<tr><td><a href="/admin/applications/%s"><strong>%s</strong></a><span class="cell-sub">%s &middot; %s</span></td><td><span class="pill %s">%s</span></td><td>%s</td><td class="why"><div class="why-clamp" title="%s">%s</div></td><td>%s</td><td><div class="row-actions">`,
				esc(a.ID), esc(a.Name), esc(osLabel(a.OS, a.Arch)), esc(a.ID), chipClass, chip, report, esc(why), esc(why), installer)
			if !a.Reviewed || (a.DeviceID == "" && a.ProvisionError == "") {
				fmt.Fprintf(&b, `<form method="post" action="/admin/applications"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s"><input type="hidden" name="action" value="approve"><button class="btn small" type="submit">Approve</button></form>`, s.csrfToken(r), a.ID)
			}
			if a.ProvisionError != "" {
				fmt.Fprintf(&b, `<form method="post" action="/admin/applications"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s"><input type="hidden" name="action" value="retry"><button class="btn ghost small" type="submit">Retry</button></form>`, s.csrfToken(r), a.ID)
			}
			fmt.Fprintf(&b, `<form method="post" action="/admin/applications" onsubmit="return confirm('Delete this application?')"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s"><input type="hidden" name="action" value="delete"><button class="btn danger small" type="submit">Delete</button></form></div></td></tr>`,
				s.csrfToken(r), a.ID)
		}
		b.WriteString(`</tbody></table></div>`)
	}
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
	b.WriteString(`<div class="admin-head"><h1>Download logins</h1></div>`)
	b.WriteString(adminSubnav("users"))
	b.WriteString(`<p class="muted">Logins are the per-device installers from before token enrolment. Machines that installed since 17 Nov appear under <a href="/admin/devices">Devices</a>.</p>`)
	if noticeHTML != "" {
		fmt.Fprintf(&b, `<div class="alert ok">%s</div>`, noticeHTML)
	}
	rows := s.deviceRows()
	fl := s.loadFleet()
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
			// A login from the pre-token era can share its key with a device
			// that enrolled later; point at that device so the two pages agree.
			if d, ok := fl.devByPub[u.Peer]; ok {
				status += fmt.Sprintf(`<span class="cell-sub">tracked as <a href="/admin/devices/%s">%s</a></span>`, esc(d.ID), esc(d.ID))
			}
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
<td><a href="/admin/users/%s"><code>%s</code></a></td>
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
				esc(row.Name), esc(row.Name), device, status, downloads, password,
				s.csrfToken(r), esc(row.Name), s.csrfToken(r), esc(row.Name))
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`<p class="muted">Worst first. Reset shows a new password once.</p>`)
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
	// A newline here would be hashed and stored, and the password shown in
	// the admin UI would then never work. Scripts post this field.
	password := strings.TrimSpace(r.FormValue("password"))
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
