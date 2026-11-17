// Command egress-enroll-agent binds a first-activation key on the exit host.
//
// The web server runs as an unprivileged account and cannot touch WireGuard.
// It writes one claim file per enrollment; this agent, running as root, checks
// the claim, appends the peer to wg0.conf, applies it live, adds the relay
// credential, and writes the result back. It only ever appends: existing peers
// and relay users are never modified or removed.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultDir  = "/var/lib/bypass/enroll"
	defaultConf = "/etc/wireguard/wg0.conf"
	defaultAuth = "/etc/egress-socks/auth"
	defaultDev  = "wg0"
)

type claim struct {
	ID        string `json:"id"`
	PubKey    string `json:"pubkey"`
	IP        string `json:"ip"`
	RelayUser string `json:"relay_user"`
	RelayPass string `json:"relay_pass"`
	Label     string `json:"label,omitempty"`
}

type result struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

var (
	idRe     = regexp.MustCompile(`^d-[0-9a-f]{8}$`)
	hexRe    = regexp.MustCompile(`^[0-9a-f]{8}$`)
	pubKeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)

type agent struct {
	dir  string
	conf string
	auth string
	dev  string
}

func main() {
	dir := os.Getenv("EGRESS_ENROLL_DIR")
	if dir == "" {
		dir = defaultDir
	}
	a := &agent{
		dir:  dir,
		conf: envOr("EGRESS_WG_CONF", defaultConf),
		auth: envOr("EGRESS_RELAY_AUTH", defaultAuth),
		dev:  envOr("EGRESS_WG_DEV", defaultDev),
	}
	if err := os.MkdirAll(a.dir, 0770); err != nil {
		log.Fatalf("enroll dir: %v", err)
	}
	// The web server, which writes claims, runs unprivileged. Hand it the
	// directory; the agent is root and does not need to own it.
	if u, err := user.Lookup("bypass"); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		if err := os.Chown(a.dir, uid, gid); err != nil {
			log.Printf("enroll dir chown: %v", err)
		}
	} else {
		log.Printf("could not look up the bypass user: %v", err)
	}
	_ = os.Chmod(a.dir, 0770)
	log.Printf("enroll agent watching %s", a.dir)
	for {
		a.cycle()
		time.Sleep(time.Second)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (a *agent) cycle() {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(a.dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var c claim
		if err := json.Unmarshal(data, &c); err != nil {
			a.finish(strings.TrimSuffix(name, ".json"), result{Error: "unreadable claim"})
			continue
		}
		if strings.TrimSuffix(name, ".json") != c.ID {
			a.finish(strings.TrimSuffix(name, ".json"), result{Error: "claim id does not match its file"})
			continue
		}
		if err := a.apply(c); err != nil {
			log.Printf("enroll %s: %v", c.ID, err)
			a.finish(c.ID, result{Error: err.Error()})
			continue
		}
		log.Printf("enroll %s: %s bound to %s", c.ID, fingerprint(c.PubKey), c.IP)
		a.finish(c.ID, result{OK: true})
	}
}

func (a *agent) finish(id string, res result) {
	data, _ := json.Marshal(res)
	tmp := filepath.Join(a.dir, id+".result.tmp")
	// Readable by the web server; it carries no secret.
	_ = os.WriteFile(tmp, data, 0644)
	_ = os.Rename(tmp, filepath.Join(a.dir, id+".result"))
	_ = os.Remove(filepath.Join(a.dir, id+".json"))
}

func (a *agent) apply(c claim) error {
	if err := validate(c); err != nil {
		return err
	}
	raw, err := os.ReadFile(a.conf)
	if err != nil {
		return fmt.Errorf("read %s: %w", a.conf, err)
	}
	conf := string(raw)
	byPub, byIP := parsePeers(conf)
	if allowed, ok := byPub[c.PubKey]; ok {
		if containsPrefix(allowed, c.IP+"/32") {
			return nil // already applied
		}
		return fmt.Errorf("public key already bound to another address")
	}
	if key, ok := byIP[c.IP]; ok && key != c.PubKey {
		return fmt.Errorf("address %s is in use", c.IP)
	}

	block := fmt.Sprintf("\n# enrolled %s %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n",
		c.ID, time.Now().UTC().Format(time.RFC3339), c.PubKey, c.IP)
	if !strings.HasSuffix(conf, "\n") {
		block = "\n" + block
	}
	if err := appendFile(a.conf, block, 0600); err != nil {
		return err
	}
	// The live peer is what makes it work now; the config only covers a restart.
	if out, err := exec.Command("wg", "set", a.dev, "peer", c.PubKey, "allowed-ips", c.IP+"/32").CombinedOutput(); err != nil {
		return fmt.Errorf("wg set: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if err := addRelayUser(a.auth, c.RelayUser, c.RelayPass); err != nil {
		return err
	}
	return nil
}

func validate(c claim) error {
	if !idRe.MatchString(c.ID) {
		return fmt.Errorf("bad device id")
	}
	if !pubKeyRe.MatchString(c.PubKey) {
		return fmt.Errorf("bad public key")
	}
	raw, err := base64.StdEncoding.DecodeString(c.PubKey)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("public key is not 32 bytes")
	}
	if !validIP(c.IP) {
		return fmt.Errorf("address outside the enrollment pool")
	}
	want := "dev-" + strings.ReplaceAll(c.IP, ".", "-") + "-"
	if !strings.HasPrefix(c.RelayUser, want) || !hexRe.MatchString(strings.TrimPrefix(c.RelayUser, want)) {
		return fmt.Errorf("relay user does not match the address")
	}
	if n := len(c.RelayPass); n < 20 || n > 64 || strings.ContainsAny(c.RelayPass, ": \t\r\n") {
		return fmt.Errorf("bad relay password")
	}
	return nil
}

func validIP(s string) bool {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return false
	}
	return ip[0] == 10 && ip[1] == 88 && ip[2] == 0 && ip[3] >= 20 && ip[3] <= 199
}

// parsePeers returns pubkey -> allowed-ips and address -> pubkey.
func parsePeers(conf string) (map[string]string, map[string]string) {
	byPub := map[string]string{}
	byIP := map[string]string{}
	var pub, allowed string
	flush := func() {
		if pub == "" {
			return
		}
		byPub[pub] = allowed
		for _, field := range strings.Split(allowed, ",") {
			field = strings.TrimSpace(field)
			if strings.HasSuffix(field, "/32") {
				byIP[strings.TrimSuffix(field, "/32")] = pub
			}
		}
	}
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "[Peer]":
			flush()
			pub, allowed = "", ""
		case strings.HasPrefix(line, "PublicKey"):
			pub = strings.TrimSpace(strings.TrimPrefix(line, "PublicKey"))
			pub = strings.TrimPrefix(pub, "=")
			pub = strings.TrimSpace(pub)
		case strings.HasPrefix(line, "AllowedIPs"):
			allowed = strings.TrimSpace(strings.TrimPrefix(line, "AllowedIPs"))
			allowed = strings.TrimPrefix(allowed, "=")
			allowed = strings.TrimSpace(allowed)
		}
	}
	flush()
	return byPub, byIP
}

func containsPrefix(list, want string) bool {
	for _, field := range strings.Split(list, ",") {
		if strings.TrimSpace(field) == want {
			return true
		}
	}
	return false
}

func addRelayUser(path, user, pass string) error {
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), user+":") {
			return fmt.Errorf("relay user already exists")
		}
	}
	line := user + ":" + pass + "\n"
	if len(raw) > 0 && !strings.HasSuffix(string(raw), "\n") {
		line = "\n" + line
	}
	if err := appendFile(path, line, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func appendFile(path, data string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(data)
	return err
}

func fingerprint(pub string) string {
	raw, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return pub
	}
	sum := sha256Sum(raw)
	return sum[:16]
}

func sha256Sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
