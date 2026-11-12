package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
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
