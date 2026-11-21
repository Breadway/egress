package egress

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"egress/internal/core"
)

// shareUsage enforces the monthly sharing limit. It counts the WireGuard
// transfer counters of the peers currently carried as an exit, keeps the
// running total across restarts in the daemon state directory, and resets when
// the calendar month changes.
type shareUsage struct {
	mu       sync.Mutex
	path     string
	month    string
	baseline uint64
	max      map[string]uint64
	limitGB  int
}

type shareUsageFile struct {
	Month string `json:"month"`
	Bytes uint64 `json:"bytes"`
}

func newShareUsage(limitGB int) *shareUsage {
	u := &shareUsage{
		path:    filepath.Join(core.StateDir(), "share-usage.json"),
		month:   time.Now().Format("2006-01"),
		max:     map[string]uint64{},
		limitGB: limitGB,
	}
	if data, err := os.ReadFile(u.path); err == nil {
		var stored shareUsageFile
		if json.Unmarshal(data, &stored) == nil && stored.Month == u.month {
			u.baseline = stored.Bytes
		}
	}
	return u
}

// Track folds the current peer counters in. Call it after the client set has
// been reconciled so removed peers do not keep counting.
func (u *shareUsage) Track(dev string, active map[string]exitClient) {
	if u.limitGB <= 0 {
		return
	}
	month := time.Now().Format("2006-01")
	u.mu.Lock()
	defer u.mu.Unlock()
	if month != u.month {
		u.month = month
		u.baseline = 0
		u.max = map[string]uint64{}
	}
	for pubkey, bytes := range wgTransfer(dev) {
		if _, carried := active[pubkey]; !carried {
			continue
		}
		if bytes > u.max[pubkey] {
			u.max[pubkey] = bytes
		}
	}
	u.saveLocked()
}

// Exceeded reports whether this month's carrying has reached the limit.
func (u *shareUsage) Exceeded() bool {
	if u.limitGB <= 0 {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.totalLocked() >= uint64(u.limitGB)*1_000_000_000
}

// Save persists the running total. Called periodically and on shutdown.
func (u *shareUsage) Save() {
	if u.limitGB <= 0 {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.saveLocked()
}

func (u *shareUsage) totalLocked() uint64 {
	total := u.baseline
	for _, bytes := range u.max {
		total += bytes
	}
	return total
}

func (u *shareUsage) saveLocked() {
	data, err := json.Marshal(shareUsageFile{Month: u.month, Bytes: u.totalLocked()})
	if err != nil {
		return
	}
	_ = os.WriteFile(u.path, data, 0600)
}

// wgTransfer returns the summed rx and tx bytes per peer. The command is the
// same on Linux and Windows when WireGuard's userspace tools are installed.
func wgTransfer(dev string) map[string]uint64 {
	out, err := exec.Command("wg", "show", dev, "transfer").Output()
	if err != nil {
		return nil
	}
	totals := map[string]uint64{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		rx, errRx := strconv.ParseUint(fields[1], 10, 64)
		tx, errTx := strconv.ParseUint(fields[2], 10, 64)
		if errRx != nil || errTx != nil {
			continue
		}
		totals[fields[0]] = rx + tx
	}
	return totals
}
