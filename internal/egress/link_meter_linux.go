//go:build linux

package egress

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// linkMeter measures the tunnel interface from the kernel counters. It is a
// display value for the Home screen, not a billing or quota source.
type linkMeter struct {
	iface  string
	last   time.Time
	lastRx uint64
	lastTx uint64
	mbps   float64
	total  uint64
}

func newLinkMeter(iface string) *linkMeter { return &linkMeter{iface: iface} }

func (m *linkMeter) Sample() (speedMbps, dataGB float64) {
	rx, okRx := m.read("rx_bytes")
	tx, okTx := m.read("tx_bytes")
	if !okRx || !okTx {
		return m.mbps, float64(m.total) / 1e9
	}
	now := time.Now()
	if !m.last.IsZero() {
		elapsed := now.Sub(m.last).Seconds()
		// Counters restart when the interface is recreated. A drop is not
		// negative traffic.
		if elapsed > 0.5 && rx >= m.lastRx && tx >= m.lastTx {
			bits := float64((rx-m.lastRx)+(tx-m.lastTx)) * 8
			m.mbps = bits / elapsed / 1e6
		}
	}
	m.last, m.lastRx, m.lastTx = now, rx, tx
	m.total = rx + tx
	return m.mbps, float64(m.total) / 1e9
}

func (m *linkMeter) read(name string) (uint64, bool) {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", m.iface, "statistics", name))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
