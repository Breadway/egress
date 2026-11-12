package main

// seedCandidates are the domains worth testing on a new network. They are not
// assumed blocked: the sweep probes each one directly and records the result in
// the network profile. The list comes from measurements on Australian school
// networks in November 2026, plus the obvious redirect targets.
var seedCandidates = []string{
	// Social and messaging
	"discord.com",
	"x.com",
	"twitter.com",
	"instagram.com",
	"facebook.com",
	"www.facebook.com",
	"tiktok.com",
	"www.tiktok.com",
	"reddit.com",
	"www.reddit.com",
	"old.reddit.com",
	// Video and streaming
	"netflix.com",
	"www.netflix.com",
	"twitch.tv",
	"www.twitch.tv",
	"youtube.com",
	"www.youtube.com",
	// Music
	"spotify.com",
	"open.spotify.com",
	// Gaming
	"store.steampowered.com",
	"steamcommunity.com",
	"poki.com",
	"www.poki.com",
	"roblox.com",
	"www.roblox.com",
	// Commonly allowed, useful as controls
	"google.com",
	"www.google.com",
	"github.com",
	"chatgpt.com",
}

// seedSet is built once for fast membership checks.
var seedSet = func() map[string]bool {
	m := make(map[string]bool, len(seedCandidates))
	for _, domain := range seedCandidates {
		m[NormalizeDomain(domain)] = true
	}
	return m
}()

// isSeedCandidate reports whether a curated site is in the seed list. A weak
// connect timeout on a curated site blocks immediately, because the seed list
// exists for networks that blackhole exactly these names.
func isSeedCandidate(domain string) bool {
	return seedSet[NormalizeDomain(domain)]
}

// SeedCandidates returns a copy so callers cannot mutate the seed.
func SeedCandidates() []string {
	out := make([]string, len(seedCandidates))
	copy(out, seedCandidates)
	return out
}
