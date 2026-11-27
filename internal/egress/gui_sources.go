package egress

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"egress/internal/guiapi"
	"egress/internal/split"
	"egress/internal/supervisor"
)

// newGUISources binds the local GUI API to the state the supervisor, the
// split controller, the peer manager and the exit router already maintain.
// Nothing here changes the tunnel; the two actions are pause/resume and a
// single-site retry.
func newGUISources(
	ctx context.Context,
	sup *supervisor.Supervisor,
	peers *peerManager,
	splitter *split.Controller,
	direct *directExit,
	plat platform,
	meter *linkMeter,
	share *exitShare,
	relay *derpTransport,
) guiapi.Sources {
	protection := func() guiapi.Protection {
		if splitter == nil {
			return guiapi.Protection{Stats: guiapi.ProtectionStats{}, Sites: []guiapi.Site{}}
		}
		exitLabel := activeExitName(direct)
		peerExit := direct != nil && direct.ActiveExitPeer()
		_, domains := splitter.StatusSnapshot()
		sites := make([]guiapi.Site, 0, len(domains))
		stats := guiapi.ProtectionStats{Unblocked: len(domains)}
		for _, d := range domains {
			site := guiapi.Site{
				Domain: d.Name,
				At:     d.LastProbe.UTC().Format(time.RFC3339),
				Retry:  d.Unserved,
			}
			if d.Unserved {
				// The router released the prefixes, so this traffic already
				// follows the physical link. "Needs retry" claimed the site was
				// unreachable while it often loads fine direct; name the route
				// instead. The pill stays clickable to queue a retry.
				site.Via, site.Label = "direct", "Direct"
				stats.Retry++
			} else {
				via, label, cloud := classifySite(d.ServedBy, exitLabel, peerExit)
				site.Via, site.Label = via, label
				if cloud {
					stats.ViaCloud++
				} else {
					stats.ViaFriend++
				}
			}
			sites = append(sites, site)
		}
		sort.SliceStable(sites, func(i, j int) bool {
			if sites[i].At != sites[j].At {
				return sites[i].At > sites[j].At
			}
			return sites[i].Domain < sites[j].Domain
		})
		return guiapi.Protection{Stats: stats, Sites: sites}
	}

	circle := func() guiapi.Circle {
		host, _ := os.Hostname()
		if host == "" {
			host = "This device"
		}
		people := []guiapi.Person{{
			ID: "self", Name: host, Kind: "device", Online: true,
			Transport: "direct", Self: true,
		}}
		exitKey := ""
		if direct != nil {
			if _, _, key, active := direct.ActiveExit(); active {
				exitKey = key
			}
		}
		if peers != nil {
			for _, p := range peers.Snapshot() {
				people = append(people, guiapi.Person{
					ID:        personID(p.Name),
					Name:      p.Name,
					Kind:      "friend",
					Online:    p.Online,
					Sharing:   exitKey != "" && p.PubKey == exitKey,
					Transport: p.Transport,
				})
			}
		}
		return guiapi.Circle{Circle: "bread", People: people}
	}

	status := func() guiapi.Status {
		online := plat.TunnelUp() || aegisReachable()
		st := guiapi.Status{
			Version:   reportVersion(),
			Online:    online,
			Connected: sup.Connected(),
			Path:      sup.Path(),
			Exit:      "Cloud relay",
			Network:   "unknown",
		}
		if direct != nil {
			if name := activeExitName(direct); name != "" {
				st.Exit = name
			}
			activeKey := ""
			if _, _, key, active := direct.ActiveExit(); active {
				activeKey = key
			}
			for _, ex := range direct.Options() {
				label := ex.Label
				if label == "" {
					label = titleName(ex.ID)
				}
				st.Exits = append(st.Exits, guiapi.ExitOption{
					ID:     ex.ID,
					Label:  label,
					Active: activeKey != "" && ex.PubKey == activeKey,
				})
			}
		}
		if splitter != nil {
			network, domains := splitter.StatusSnapshot()
			if network != "" {
				st.Network = network
			}
			st.UnblockedToday = len(domains)
		}
		if peers != nil {
			for _, p := range peers.Snapshot() {
				if p.Online {
					st.CircleOnline++
				}
			}
		}
		if meter != nil {
			st.SpeedMbps, st.DataGB = meter.Sample()
		}
		return st
	}

	return guiapi.Sources{
		Version:    reportVersion(),
		Status:     status,
		Circle:     circle,
		Protection: protection,
		Retry:      func(domain string) bool { return splitter != nil && splitter.Retry(domain) },
		Observe: func(domain string) {
			if splitter != nil {
				splitter.Observe(domain)
			}
		},
		SetConnected: sup.SetConnected,
		Admin:        newAdminProxy(),
		ApplySettings: func(s guiapi.Settings) error {
			applyRuntimeSettings(ctx, sup, peers, splitter, share, relay, s)
			if direct != nil {
				if err := direct.SetChoice(s.ExitChoice); err != nil {
					return fmt.Errorf("exit choice: %w", err)
				}
			}
			if s.ConnectAutomatically != !bootDisabled() {
				if err := setBootStart(s.ConnectAutomatically); err != nil {
					return fmt.Errorf("boot start: %w", err)
				}
				// The marker outlives reinstalls and updates, so it has to
				// move with the unit or an update silently re-enables boot.
				if err := setBootPreference(!s.ConnectAutomatically); err != nil {
					return fmt.Errorf("boot preference: %w", err)
				}
			}
			return nil
		},
	}
}

// applyRuntimeSettings applies everything that can change while the service
// runs. Boot start is separate because a manual CLI disable must survive a
// daemon restart.
func applyRuntimeSettings(ctx context.Context, sup *supervisor.Supervisor, peers *peerManager, splitter *split.Controller, share *exitShare, relay *derpTransport, s guiapi.Settings) {
	sup.SetFallback(s.RelayFallback && s.Mode != guiapi.ModeDirect)
	if peers != nil {
		peers.SetHiddenAddress(s.HidePublicAddress || s.RelayOnly)
	}
	if splitter != nil {
		splitter.SetShareReports(s.ShareReports)
	}
	if share != nil {
		opts := defaultExitServeOptions()
		// The relay's region is fixed when the daemon starts, so serving
		// reuses that connection rather than opening a second identity.
		opts.Relay = relay
		opts.LimitGB = s.ShareLimitGB
		enabled := s.ShareConnection && s.ShareScope != "none"
		if runtime.GOOS != "linux" {
			if enabled {
				appLogger().Printf("share: serving an exit is Linux only; the preference is stored")
			}
			enabled = false
		}
		share.Apply(ctx, enabled, opts)
	}
}

// relayRegionCode maps the user-facing region name to the DERP region code.
// Empty means automatic: the transport keeps its existing default.
func relayRegionCode(setting string) string {
	switch setting {
	case "sydney":
		return "syd"
	case "singapore":
		return "sin"
	case "los_angeles":
		return "lax"
	default:
		return ""
	}
}

// classifySite decides whether a served site went through a friend, a
// published exit server, or the cloud relay. A published direct exit is not a
// friend even though it appears in the client's exit list.
func classifySite(servedBy, exitLabel string, peerExit bool) (via, label string, cloud bool) {
	servedBy = strings.TrimSpace(servedBy)
	switch {
	case servedBy != "" && !strings.EqualFold(servedBy, "aegis") && !strings.EqualFold(servedBy, "cloud"):
		if exitLabel != "" && strings.EqualFold(servedBy, exitLabel) && !peerExit {
			return "cloud", titleName(servedBy), true
		}
		return "friend", titleName(servedBy), false
	case exitLabel != "":
		if peerExit {
			return "friend", exitLabel, false
		}
		return "cloud", exitLabel, true
	default:
		return "cloud", "Cloud relay", true
	}
}

// activeExitName is the display name of the peer exit currently carrying
// blocked traffic, or empty when the cloud relay is the path.
func activeExitName(direct *directExit) string {
	if direct == nil {
		return ""
	}
	label, _, _, active := direct.ActiveExit()
	if !active || label == "" {
		return ""
	}
	label = titleName(label)
	if strings.EqualFold(label, "Aegis") || strings.EqualFold(label, "Cloud relay") {
		return ""
	}
	return label
}

// personID is a stable, lowercase handle for a circle member. It never leaves
// the daemon as a key or address; it is only a list key for the UI.
func personID(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "person"
	}
	return out
}

// titleName turns a published exit id such as "hestia" into the display name
// the rest of the app uses.
func titleName(name string) string {
	if name == "" {
		return name
	}
	parts := strings.Fields(strings.ReplaceAll(name, "_", " "))
	for i, part := range parts {
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}
