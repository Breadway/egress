package split

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"egress/internal/core"
)

// Overrides are the operator's local decisions about specific domains:
// split-allow.txt forces a domain direct, split-block.txt forces it through
// the tunnel. They beat both probing and the shared table, because a wrong
// classification should not need a release.
type Overrides struct {
	Allow map[string]bool
	Block map[string]bool
}

// LoadOverrides reads the two files from dir. Missing files are empty lists.
func LoadOverrides(dir string) Overrides {
	o := Overrides{Allow: map[string]bool{}, Block: map[string]bool{}}
	for _, item := range []struct {
		name string
		into map[string]bool
	}{
		{"split-allow.txt", o.Allow},
		{"split-block.txt", o.Block},
	} {
		readDomainFile(filepath.Join(dir, item.name), item.into)
	}
	return o
}

func readDomainFile(path string, into map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := core.NormalizeDomain(line)
		if domain != "" && plausibleDomain(domain) {
			into[domain] = true
		}
	}
}

// Forced returns the override state for a domain, if there is one.
func (o Overrides) Forced(domain string) (DomainState, bool) {
	domain = core.NormalizeDomain(domain)
	if o.Allow[domain] {
		return StateAllowed, true
	}
	if o.Block[domain] {
		return StateBlocked, true
	}
	return StateUnknown, false
}

// Allowed reports whether the domain is pinned direct.
func (o Overrides) Allowed(domain string) bool {
	return o.Allow[core.NormalizeDomain(domain)]
}

// OverrideSummary reports how many rules each file holds, for diagnose.
func OverrideSummary(dir string) []string {
	var out []string
	for _, name := range []string{"split-allow.txt", "split-block.txt"} {
		set := map[string]bool{}
		readDomainFile(filepath.Join(dir, name), set)
		out = append(out, fmt.Sprintf("%s: %d", name, len(set)))
	}
	return out
}

// ProfileSummary reports the newest profile's protocol picture and conflict
// count for diagnose. It reads files rather than a live controller because
// diagnose runs as a separate process.
func ProfileSummary(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var newest string
	var newestMod int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "split-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if m := info.ModTime().UnixNano(); m > newestMod {
			newest, newestMod = filepath.Join(dir, e.Name()), m
		}
	}
	if newest == "" {
		return nil
	}
	profile, err := LoadProfile(newest, "")
	if err != nil {
		return []string{"profile unreadable: " + err.Error()}
	}
	protos := make([]string, 0, len(profile.Protocols))
	for k, v := range profile.Protocols {
		protos = append(protos, k+"="+v)
	}
	sort.Strings(protos)
	blocked, contested := 0, 0
	for _, entry := range profile.Entries {
		if entry.State == StateBlocked {
			blocked++
			if entry.Contested {
				contested++
			}
		}
	}
	return []string{
		"profile: " + filepath.Base(newest),
		"protocols: " + strings.Join(protos, " "),
		"blocked domains: " + strconv.Itoa(blocked) + ", contested: " + strconv.Itoa(contested),
	}
}

// AppendOverride adds one domain to the allow or block file, creating it if
// needed. The tray uses it so a wrong decision is one click, not an edit.
func AppendOverride(dir, domain string, allow bool) error {
	domain = core.NormalizeDomain(domain)
	if domain == "" {
		return os.ErrInvalid
	}
	name := "split-block.txt"
	if allow {
		name = "split-allow.txt"
	}
	path := filepath.Join(dir, name)
	set := map[string]bool{}
	readDomainFile(path, set)
	if set[domain] {
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(domain + "\n")
	return err
}
