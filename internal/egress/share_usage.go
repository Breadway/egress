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

// shareUsage enforces the monthly sharing limit. It accumulates per-peer
// counter deltas rather than storing a raw total, so traffic is counted once
// across reconnects and daemon restarts, including the case where WireGuard's
// counters survive a restart.
type shareUsage struct {
	mu      sync.Mutex
	path    string
	month   string
	total   uint64
	last    map[string]uint64
	limitGB int
}

type shareUsageFile struct {
	Month string            `json:"month"`
	Total uint64            `json:"total"`
	Peers map[string]uint64 `json:"peers,omitempty"`
}

func newShareUsage(limitGB int) *shareUsage {
	u := &shareUsage{
		path:    filepath.Join(core.StateDir(), "share-usage.json"),
		month:   time.Now().Format("2006-01"),
		last:    map[string]uint64{},
		limitGB: limitGB,
	}
	if data, err := os.ReadFile(u.path); err == nil {
		var stored shareUsageFile
		if json.Unmarshal(data, &stored) == nil && stored.Month == u.month {
			u.total = stored.Total
			if stored.Peers != nil {
				u.last = stored.Peers
			}
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
		u.total = 0
		u.last = map[string]uint64{}
	}
	// A peer that is gone cannot be sampled again; drop its baseline without
	// changing the accumulated total.
	for key := range u.last {
		if _, carried := active[key]; !carried {
			delete(u.last, key)
		}
	}
	for pubkey, bytes := range wgTransferCommand(dev) {
		if _, carried := active[pubkey]; !carried {
			continue
		}
		prev, seen := u.last[pubkey]
		switch {
		case !seen:
			// First sample: everything the counter holds happened while it
			// was carried, so it all counts.
			u.total += bytes
		case bytes >= prev:
			u.total += bytes - prev
		default:
			// WireGuard restarted the counter with a re-added peer. The new
			// value is all fresh traffic, not a negative delta.
			u.total += bytes
		}
		u.last[pubkey] = bytes
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
	return u.total >= uint64(u.limitGB)*1_000_000_000
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

func (u *shareUsage) saveLocked() {
	data, err := json.Marshal(shareUsageFile{Month: u.month, Total: u.total, Peers: u.last})
	if err != nil {
		return
	}
	_ = os.WriteFile(u.path, data, 0600)
}

// wgTransferCommand is a variable so tests can drive accounting without a
// live WireGuard interface.
var wgTransferCommand = wgTransfer

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
