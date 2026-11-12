package main

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// The update service is public; the admin views only need the current version
// string, cached so a page view does not depend on the network every time.
const manifestURL = "https://dns.breadway.dev/updates/manifest"

type releaseCache struct {
	mu      sync.Mutex
	version string
	at      time.Time
}

var latestVersionCache releaseCache

// latestRelease returns the published version for a target, or "" when the
// service cannot be reached. Cached for five minutes.
func latestRelease(goos, goarch string) string {
	latestVersionCache.mu.Lock()
	defer latestVersionCache.mu.Unlock()
	if time.Since(latestVersionCache.at) < 5*time.Minute {
		return latestVersionCache.version
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(manifestURL + "?os=" + goos + "&arch=" + goarch)
	if err != nil {
		return latestVersionCache.version
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return latestVersionCache.version
	}
	var m struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&m); err != nil {
		return latestVersionCache.version
	}
	latestVersionCache.version = m.Version
	latestVersionCache.at = time.Now()
	return m.Version
}
