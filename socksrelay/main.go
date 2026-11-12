package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:7109", "loopback address to listen on")
	authFile := flag.String("auth-file", "/etc/egress-socks/auth", "file of user:password lines")
	idle := flag.Duration("idle", 5*time.Minute, "handshake deadline")
	limitMbps := flag.Float64("limit-mbps", 0, "aggregate relay throughput cap in Mbit/s (0 = unlimited)")
	perUser := flag.Float64("limit-mbps-per-user", 0, "per-user throughput cap in Mbit/s (0 = unlimited)")
	ownerUser := flag.String("owner-user", "", "relay user that gets the owner cap")
	ownerMbps := flag.Float64("owner-mbps", 0, "throughput cap for the owner user in Mbit/s")
	usageFile := flag.String("usage-file", "", "write a per-user byte snapshot here every few minutes")
	dailyQuotaMB := flag.Float64("daily-quota-mb", 0, "per-user daily byte quota in MB (0 = unlimited)")
	flag.Parse()

	users, err := loadAuth(*authFile)
	if err != nil {
		log.Fatalf("socksrelay: %v", err)
	}
	if len(users) == 0 {
		log.Fatal("socksrelay: auth file has no users")
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("socksrelay: %v", err)
	}
	log.Printf("socksrelay: listening on %s with %d user(s)", *listen, len(users))

	r := newRelay(users, *idle)
	r.limit = newLimiter(*limitMbps * 1e6 / 8)
	if r.limit != nil {
		log.Printf("socksrelay: aggregate cap %.1f Mbit/s", *limitMbps)
	}
	r.perUser = map[string]*limiter{}
	for user := range users {
		rate := *perUser
		if user == *ownerUser && *ownerMbps > 0 {
			rate = *ownerMbps
		}
		if rate > 0 {
			r.perUser[user] = newLimiter(rate * 1e6 / 8)
		}
	}
	if *perUser > 0 {
		log.Printf("socksrelay: per-user cap %.1f Mbit/s", *perUser)
	}
	if *ownerUser != "" && *ownerMbps > 0 {
		log.Printf("socksrelay: owner %s cap %.1f Mbit/s", *ownerUser, *ownerMbps)
	}
	r.usage = newUsage()
	r.quotaBytes = int64(*dailyQuotaMB * 1024 * 1024)
	if r.quotaBytes > 0 {
		log.Printf("socksrelay: per-user daily quota %.0f MB", *dailyQuotaMB)
	}
	r.perUserRate = *perUser * 1e6 / 8
	go watchAuth(*authFile, r)
	if *usageFile != "" {
		go writeUsageLoop(*usageFile, r)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("socksrelay: accept: %v", err)
			continue
		}
		go r.handle(conn)
	}
}

// loadAuth reads user:password lines. Comments and blank lines are ignored;
// malformed lines fail closed rather than silently dropping a credential.
func loadAuth(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	users := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, pass, ok := strings.Cut(line, ":")
		if !ok || user == "" || pass == "" {
			return nil, fmt.Errorf("%s:%d: want user:password", path, i+1)
		}
		users[user] = pass
	}
	return users, nil
}

// watchAuth reloads the auth file when it changes, so an admin revocation takes
// effect without a restart. A malformed edit keeps the previous table.
func watchAuth(path string, r *relay) {
	var last time.Time
	for {
		time.Sleep(30 * time.Second)
		info, err := os.Stat(path)
		if err != nil || info.ModTime().Equal(last) {
			continue
		}
		users, err := loadAuth(path)
		if err != nil || len(users) == 0 {
			log.Printf("socksrelay: auth reload skipped: %v", err)
			continue
		}
		r.setUsers(users)
		last = info.ModTime()
		log.Printf("socksrelay: auth reloaded, %d user(s)", len(users))
	}
}

// writeUsageLoop snapshots bytes per user so the admin page can show usage.
func writeUsageLoop(path string, r *relay) {
	for {
		writeUsageOnce(path, r)
		time.Sleep(5 * time.Minute)
	}
}

func writeUsageOnce(path string, r *relay) {
	snapshot := r.usage.snapshot()
	payload, err := json.MarshalIndent(struct {
		Updated string           `json:"updated"`
		Users   map[string]int64 `json:"users"`
	}{time.Now().UTC().Format(time.RFC3339), snapshot}, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
