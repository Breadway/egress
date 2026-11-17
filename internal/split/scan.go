package split

import (
	"context"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultScanDomains is a curated starter set for a new network: the services
// most often filtered, across social, messaging, video, news, developer and
// adult categories, plus a few names that are almost never blocked so a clean
// result is distinguishable from a dead probe.
func DefaultScanDomains() []string {
	return []string{
		// search and big platforms
		"google.com", "www.google.com", "youtube.com", "facebook.com", "instagram.com",
		"whatsapp.com", "web.whatsapp.com", "x.com", "twitter.com", "tiktok.com",
		"reddit.com", "wikipedia.org", "amazon.com", "netflix.com", "spotify.com",
		"microsoft.com", "apple.com", "github.com", "cloudflare.com", "linkedin.com",
		"pinterest.com", "tumblr.com", "snapchat.com", "threads.net", "mastodon.social",
		// messaging and voice
		"telegram.org", "t.me", "discord.com", "discord.gg", "signal.org",
		"messenger.com", "viber.com", "line.me", "wechat.com", "kakao.com",
		// video and streaming
		"twitch.tv", "vimeo.com", "dailymotion.com", "rumble.com", "odysee.com",
		"bitchute.com", "kick.com", "crunchyroll.com", "hbomax.com", "disneyplus.com",
		"primevideo.com", "hulu.com", "paramountplus.com", "peacocktv.com",
		// music and podcasts
		"soundcloud.com", "bandcamp.com", "deezer.com", "tidal.com", "podcasts.apple.com",
		// gaming
		"steamcommunity.com", "store.steampowered.com", "epicgames.com", "roblox.com",
		"minecraft.net", "ea.com", "ubisoft.com", "battle.net", "riotgames.com",
		"playstation.com", "xbox.com", "nintendo.com",
		// news and reference
		"bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "reuters.com",
		"apnews.com", "aljazeera.com", "dw.com", "lemonde.fr", "spiegel.de",
		"archive.org", "wikileaks.org", "medium.com", "substack.com", "quora.com",
		// developer and tools
		"stackoverflow.com", "gitlab.com", "bitbucket.org", "docker.com", "npmjs.com",
		"pypi.org", "rust-lang.org", "golang.org", "python.org", "nodejs.org",
		"sourceforge.net", "gitea.com", "codeberg.org",
		// cloud and productivity
		"dropbox.com", "drive.google.com", "onedrive.live.com", "notion.so", "slack.com",
		"zoom.us", "teams.microsoft.com", "calendar.google.com", "mail.google.com",
		"outlook.com", "proton.me", "protonmail.com", "tutanota.com", "fastmail.com",
		// shopping and services
		"ebay.com", "aliexpress.com", "temu.com", "etsy.com", "paypal.com",
		"stripe.com", "wise.com", "booking.com", "airbnb.com", "uber.com",
		// connectivity and DNS
		"cloudflare-dns.com", "dns.google", "quad9.net", "1.1.1.1", "speedtest.net",
		"fast.com", "msftconnecttest.com",
		// VPN and privacy vendors (often blocked where filtering exists)
		"protonvpn.com", "nordvpn.com", "expressvpn.com", "mullvad.net", "torproject.org",
		"tails.net",
		// file sharing
		"mega.nz", "wetransfer.com", "mediafire.com", "sendspace.com",
		// adult (frequently filtered; kept last so output stays readable)
		"pornhub.com", "xvideos.com", "xnxx.com", "redtube.com", "onlyfans.com",
	}
}

// ScanOptions configures a bulk probe.
type ScanOptions struct {
	Concurrency int
	Timeout     time.Duration
	Interface   string
	// Resolve overrides name resolution. The CLI points it at the egress
	// listener so a broken /etc/resolv.conf cannot fail a scan.
	Resolve func(context.Context, string) ([]net.IP, error)
}

// ScanResult is one classification from a bulk probe.
type ScanResult struct {
	Domain   string
	State    DomainState
	Evidence Evidence
	Err      error
}

// ScanDomains probes the list with a bounded worker pool. It is meant to seed
// a network: a few hundred domains, not a crawler.
func ScanDomains(ctx context.Context, domains []string, opts ScanOptions) []ScanResult {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.Timeout <= 0 {
		opts.Timeout = ProbeTimeout
	}
	results := make([]ScanResult, len(domains))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for i, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		wg.Add(1)
		go func(i int, domain string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			res := ProbeConfirmed(ctx, domain, ProbeOptions{Interface: opts.Interface, Timeout: opts.Timeout, Resolve: opts.Resolve})
			results[i] = ScanResult{Domain: domain, State: res.State, Evidence: res.Evidence, Err: res.Err}
		}(i, domain)
	}
	wg.Wait()
	return results
}

// RecordScanIn writes a scan's findings into the profile for a network.
// Transient failures are ignored: a probe that could not resolve says nothing
// about the network.
func RecordScanIn(dir, network string, results []ScanResult) (int, error) {
	path := ProfilePathIn(dir, network)
	profile, err := LoadProfile(path, network)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	changed := 0
	for _, r := range results {
		if r.State == StateUnknown || r.Domain == "" {
			continue
		}
		if recordProbeOutcome(profile, r.Domain, ProbeResult{State: r.State, Evidence: r.Evidence}, now) {
			changed++
		}
	}
	if changed == 0 {
		return 0, nil
	}
	return changed, profile.Save(path)
}

// RecordScan is RecordScanIn against the system profile directory.
func RecordScan(network string, results []ScanResult) (int, error) {
	return RecordScanIn(ProfileDir(), network, results)
}

// ReportScan shares the blocked findings so other devices on the network start
// with them. Best effort: a failed report never fails the scan.
func ReportScan(ctx context.Context, network string, results []ScanResult) {
	reporter := newSplitReporter(network, ProfileDir(), log.New(os.Stderr, "", 0))
	for _, r := range results {
		if r.State == StateBlocked {
			reporter.Report(r.Domain, r.Evidence)
		}
	}
	_ = reporter.flush(ctx)
}
