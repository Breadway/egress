// Package guiapi serves the local JSON API behind the egress user app.
//
// The daemon remains the only component that owns the tunnel. This package is
// deliberately a thin read model plus a small set of allowlisted actions:
// connection state, the circle, protection, activity and settings. It never
// accepts shell commands or file paths from the UI.
//
// The listener is the same loopback portal listener. Every request carries a
// bearer token written to a local file for the signed-in user.
package guiapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"egress/internal/core"
)

// Mode is how the user asked egress to choose a path.
type Mode string

const (
	ModeAutomatic Mode = "automatic"
	ModeDirect    Mode = "direct"
	ModeFriend    Mode = "friend"
)

// Status is the Home screen's whole model.
type Status struct {
	Version        string    `json:"version"`
	Online         bool      `json:"online"`
	Connected      bool      `json:"connected"`
	ConnectedSince time.Time `json:"connected_since"`
	Mode           Mode      `json:"mode"`
	Path           string    `json:"path"`
	Exit           string    `json:"exit"`
	SpeedMbps      float64   `json:"speed_mbps"`
	DataGB         float64   `json:"data_gb"`
	UnblockedToday int       `json:"unblocked_today"`
	CircleOnline   int       `json:"circle_online"`
	Network        string    `json:"network"`
}

// Person is one device or friend in the circle. No keys, addresses or relay
// identifiers are exposed.
type Person struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"` // device or friend
	Online    bool   `json:"online"`
	Sharing   bool   `json:"sharing"`   // their connection is carrying yours
	Transport string `json:"transport"` // direct, relay or offline
	LastSeen  string `json:"last_seen,omitempty"`
	Self      bool   `json:"self"`
}

// Circle is the named group and its people.
type Circle struct {
	Circle string   `json:"circle"`
	People []Person `json:"people"`
}

// ProtectionStats are the four counts on the Protection screen.
type ProtectionStats struct {
	Unblocked int `json:"unblocked"`
	ViaFriend int `json:"via_friend"`
	ViaCloud  int `json:"via_cloud"`
	Retry     int `json:"retry"`
}

// Site is one blocked site as the user sees it. Label is the human name of
// the exit ("Hestia", "cloud relay") while Via is the coarse kind.
type Site struct {
	Domain string `json:"domain"`
	Via    string `json:"via"` // friend, cloud, direct, none
	Label  string `json:"label"`
	At     string `json:"at"`
	Retry  bool   `json:"retry"`
}

// Protection is the Protection screen's model.
type Protection struct {
	Stats ProtectionStats `json:"stats"`
	Sites []Site          `json:"sites"`
}

// Event is one Activity row.
type Event struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"` // connection, friend, protection
	Title  string    `json:"title"`
	Detail string    `json:"detail"`
}

// Activity is the Activity screen's model.
type Activity struct {
	Events []Event `json:"events"`
}

// Settings is the persisted user preference set. Fields that the daemon can
// act on now are applied by the caller's ApplySettings hook; the rest are
// stored for the screens that own them.
type Settings struct {
	ConnectAutomatically bool   `json:"connect_automatically"`
	SmartRouting         bool   `json:"smart_routing"`
	RelayFallback        bool   `json:"relay_fallback"`
	RelayRegion          string `json:"relay_region"`
	ShareConnection      bool   `json:"share_connection"`
	ShareScope           string `json:"share_scope"`
	ShareLimitGB         int    `json:"share_limit_gb"`
	HidePublicAddress    bool   `json:"hide_public_address"`
	RelayOnly            bool   `json:"relay_only"`
	ShareReports         bool   `json:"share_reports"`
	NotifyFriend         bool   `json:"notify_friend"`
	NotifySite           bool   `json:"notify_site"`
	NotifyDrop           bool   `json:"notify_drop"`
	TextSize             string `json:"text_size"`
	Mode                 Mode   `json:"mode"`
}

// DefaultSettings is what a fresh install starts from.
func DefaultSettings() Settings {
	return Settings{
		ConnectAutomatically: true,
		SmartRouting:         true,
		RelayFallback:        true,
		RelayRegion:          "automatic",
		ShareConnection:      false,
		ShareScope:           "friends",
		ShareLimitGB:         50,
		HidePublicAddress:    false,
		RelayOnly:            false,
		ShareReports:         true,
		NotifyFriend:         true,
		NotifySite:           false,
		NotifyDrop:           true,
		TextSize:             "comfortable",
		Mode:                 ModeAutomatic,
	}
}

// Sources is everything the API reads or acts on. The egress daemon wires
// these closures to the supervisor, peer manager and split controller.
type Sources struct {
	Version       string
	Status        func() Status
	Circle        func() Circle
	Protection    func() Protection
	Retry         func(domain string) bool
	Observe       func(domain string)
	SetConnected  func(connected bool) error
	ApplySettings func(Settings) error
}

// Server owns the token, the settings file, the activity ring and the SSE
// subscribers. Create one per daemon process.
type Server struct {
	src   Sources
	token string

	settingsPath string
	activityPath string

	mu       sync.Mutex
	settings Settings
	events   []Event
	prev     snapshot
	since    time.Time

	subMu sync.Mutex
	subs  map[chan Event]struct{}
}

type snapshot struct {
	status Status
	circle Circle
	sites  map[string]Site
}

const (
	maxEvents    = 200
	maxPerSample = 12
)

// New starts a server. tokenPath is where the bearer token is written; an
// empty tokenPath keeps the token in memory (tests).
func New(src Sources, tokenPath string) (*Server, error) {
	s := &Server{
		src:          src,
		settingsPath: filepath.Join(core.StateDir(), "gui-settings.json"),
		activityPath: filepath.Join(core.StateDir(), "gui-activity.json"),
		subs:         map[chan Event]struct{}{},
		settings:     DefaultSettings(),
	}
	if tokenPath != "" {
		token, err := loadOrCreateToken(tokenPath)
		if err != nil {
			return nil, err
		}
		s.token = token
	}
	// New installs that have not written settings yet keep defaults. A
	// malformed file is not fatal: the GUI can still connect and rewrite it.
	if s.settingsPath != "" {
		s.loadSettings()
		s.loadActivity()
	}
	return s, nil
}

// Token is exposed for tests and for the log line that tells the daemon where
// the token lives. Never log the token itself.
func (s *Server) Token() string { return s.token }

// CurrentSettings returns the persisted preferences loaded at startup. The
// daemon uses it to restore relay fallback before the first request.
func (s *Server) CurrentSettings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

func loadOrCreateToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if token := strings.TrimSpace(string(data)); token != "" {
			return token, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("api token: %w", err)
	}
	token := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}
	// The file is readable by local users by design: the API is loopback
	// only and the alternative is a root prompt for every GUI launch. The
	// Unix socket with peer credentials is the upgrade path in API.md.
	if err := os.WriteFile(path, []byte(token+"\n"), 0644); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Server) loadSettings() {
	s.settings = LoadSettings()
}

// LoadSettings reads the persisted preferences without starting a server. The
// daemon uses it before the relay and sharing are created, so the saved region
// and sharing choice apply from the first connection.
func LoadSettings() Settings {
	settings := DefaultSettings()
	data, err := os.ReadFile(filepath.Join(core.StateDir(), "gui-settings.json"))
	if err != nil {
		return settings
	}
	var loaded Settings
	if json.Unmarshal(data, &loaded) == nil {
		return normalizeSettings(loaded)
	}
	return settings
}

func (s *Server) saveSettings() error {
	data, err := json.MarshalIndent(s.settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.settingsPath, append(data, '\n'), 0600)
}

func (s *Server) loadActivity() {
	data, err := os.ReadFile(s.activityPath)
	if err != nil {
		return
	}
	var events []Event
	if json.Unmarshal(data, &events) == nil && len(events) > 0 {
		if len(events) > maxEvents {
			events = events[len(events)-maxEvents:]
		}
		s.events = events
	}
}

func (s *Server) saveActivityLocked() {
	if s.activityPath == "" {
		return
	}
	data, err := json.Marshal(s.events)
	if err != nil {
		return
	}
	_ = os.WriteFile(s.activityPath, data, 0600)
}

// Handler returns the /api/v1 subtree. Mount it at /api/v1/.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", s.guard(s.Status))
	mux.HandleFunc("/api/v1/connection", s.guard(s.Connection))
	mux.HandleFunc("/api/v1/circle", s.guard(s.Circle))
	mux.HandleFunc("/api/v1/protection", s.guard(s.Protection))
	mux.HandleFunc("/api/v1/protection/retry", s.guard(s.RetrySite))
	mux.HandleFunc("/api/v1/protection/report", s.guard(s.ReportSite))
	mux.HandleFunc("/api/v1/activity", s.guard(s.Activity))
	mux.HandleFunc("/api/v1/settings", s.guard(s.Settings))
	mux.HandleFunc("/api/v1/events", s.guard(s.Events))
	return cors(mux)
}

// Runs reports whether protection is on, so the SSE stream can also deliver
// changes without waiting for the next poll.
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !s.authorized(r) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "a valid local token is required")
			return
		}
		next(w, r)
	}
}

func (s *Server) authorized(r *http.Request) bool {
	if s.token == "" {
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

// Status answers GET /api/v1/status.
func (s *Server) Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method", "GET only")
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

func (s *Server) status() Status {
	st := s.src.Status()
	s.mu.Lock()
	st.Mode = s.settings.Mode
	st.ConnectedSince = s.since
	s.mu.Unlock()
	if !st.Connected {
		st.Path = "off"
	}
	return st
}

// Connection answers POST /api/v1/connection.
func (s *Server) Connection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method", "POST only")
		return
	}
	var body struct {
		Connected *bool `json:"connected"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Connected == nil {
		writeError(w, http.StatusBadRequest, "body", `expected {"connected": true|false}`)
		return
	}
	if s.src.SetConnected == nil {
		writeError(w, http.StatusNotImplemented, "unsupported", "connection control is not available")
		return
	}
	if err := s.src.SetConnected(*body.Connected); err != nil {
		writeError(w, http.StatusInternalServerError, "connection", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

// Circle answers GET /api/v1/circle.
func (s *Server) Circle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method", "GET only")
		return
	}
	c := s.src.Circle()
	if c.People == nil {
		c.People = []Person{}
	}
	if c.Circle == "" {
		c.Circle = "bread"
	}
	writeJSON(w, http.StatusOK, c)
}

// Protection answers GET /api/v1/protection.
func (s *Server) Protection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method", "GET only")
		return
	}
	p := s.src.Protection()
	if p.Sites == nil {
		p.Sites = []Site{}
	}
	writeJSON(w, http.StatusOK, p)
}

// RetrySite answers POST /api/v1/protection/retry.
func (s *Server) RetrySite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method", "POST only")
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || strings.TrimSpace(body.Domain) == "" {
		writeError(w, http.StatusBadRequest, "body", `expected {"domain": "example.com"}`)
		return
	}
	if s.src.Retry == nil || !s.src.Retry(body.Domain) {
		writeError(w, http.StatusNotFound, "unknown", "that site is not in the blocked list")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ReportSite answers POST /api/v1/protection/report for a site the user cannot
// open. It queues one probe; a confirmed block joins the profile the same way
// a learned one does.
func (s *Server) ReportSite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method", "POST only")
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "body", `expected {"domain": "example.com"}`)
		return
	}
	domain := normalizeDomain(body.Domain)
	if !validDomain(domain) {
		writeError(w, http.StatusBadRequest, "domain", "that does not look like a site name")
		return
	}
	if s.src.Observe == nil {
		writeError(w, http.StatusNotImplemented, "unsupported", "site reporting is not available")
		return
	}
	s.src.Observe(domain)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func normalizeDomain(raw string) string {
	domain := strings.ToLower(strings.TrimSpace(raw))
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	if i := strings.IndexAny(domain, "/?#"); i >= 0 {
		domain = domain[:i]
	}
	return strings.TrimSuffix(domain, ".")
}

func validDomain(domain string) bool {
	if len(domain) < 3 || len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// Activity answers GET and DELETE /api/v1/activity?limit=50.
func (s *Server) Activity(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodDelete:
		s.mu.Lock()
		s.events = nil
		s.saveActivityLocked()
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	case http.MethodGet:
	default:
		writeError(w, http.StatusMethodNotAllowed, "method", "GET or DELETE")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &limit); err != nil || limit <= 0 {
			limit = 50
		}
	}
	s.mu.Lock()
	events := append([]Event(nil), s.events...)
	s.mu.Unlock()
	// Newest first, like the screen.
	sort.Slice(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	if limit < len(events) {
		events = events[:limit]
	}
	if events == nil {
		events = []Event{}
	}
	writeJSON(w, http.StatusOK, Activity{Events: events})
}

// Settings answers GET and PATCH /api/v1/settings.
func (s *Server) Settings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		settings := s.settings
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, settings)
	case http.MethodPatch:
		s.patchSettings(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method", "GET or PATCH")
	}
}

func (s *Server) patchSettings(w http.ResponseWriter, r *http.Request) {
	var patch map[string]json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest, "body", "expected a JSON object")
		return
	}
	s.mu.Lock()
	next := s.settings
	s.mu.Unlock()
	if err := applyPatch(&next, patch); err != nil {
		writeError(w, http.StatusBadRequest, "settings", err.Error())
		return
	}
	next = normalizeSettings(next)
	s.mu.Lock()
	s.settings = next
	s.mu.Unlock()
	if s.settingsPath != "" {
		if err := s.saveSettings(); err != nil {
			writeError(w, http.StatusInternalServerError, "settings", err.Error())
			return
		}
	}
	if s.src.ApplySettings != nil {
		if err := s.src.ApplySettings(next); err != nil {
			writeError(w, http.StatusInternalServerError, "apply", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, next)
}

// applyPatch decodes only the keys present so a partial update is not read as
// a request to reset everything else.
func applyPatch(dst *Settings, patch map[string]json.RawMessage) error {
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func normalizeSettings(v Settings) Settings {
	def := DefaultSettings()
	switch v.RelayRegion {
	case "automatic", "sydney", "singapore", "los_angeles":
	default:
		v.RelayRegion = def.RelayRegion
	}
	switch v.ShareScope {
	case "friends", "none":
	case "close":
		// The circle has no close-friends subset yet. An old value must not
		// silently disable sharing.
		v.ShareScope = "friends"
	default:
		v.ShareScope = def.ShareScope
	}
	switch v.TextSize {
	case "comfortable", "compact", "large":
	default:
		v.TextSize = def.TextSize
	}
	switch v.Mode {
	case ModeAutomatic, ModeDirect, ModeFriend:
	default:
		v.Mode = def.Mode
	}
	if v.ShareLimitGB <= 0 {
		v.ShareLimitGB = def.ShareLimitGB
	}
	return v
}
