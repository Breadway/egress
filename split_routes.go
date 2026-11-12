package main

import (
	"log"
	"net"
	"os/exec"
	"sync"
	"time"
)

const (
	// Route lifetimes. The DNS TTL is honoured with a floor so short TTLs do
	// not thrash the table, and a cap so a stale entry cannot live for days.
	routeMinTTL     = 10 * time.Minute
	routeMaxTTL     = 6 * time.Hour
	maxSplitRoutes  = 500
	routeCleanEvery = 60 * time.Second
)

// routeRunner runs one `ip route` invocation. Tests replace it.
type routeRunner func(args ...string) error

// routeManager owns the /32 routes that send learned-blocked destinations into
// wg0. Routes disappear with the interface, but expiry keeps the table small
// between network changes.
type routeManager struct {
	mu     sync.Mutex
	dev    string
	log    *log.Logger
	run    routeRunner
	routes map[string]time.Time
	order  []string
}

func newRouteManager(dev string, logger *log.Logger) *routeManager {
	return &routeManager{
		dev:    dev,
		log:    logger,
		routes: map[string]time.Time{},
		run: func(args ...string) error {
			return exec.Command("ip", args...).Run()
		},
	}
}

func (m *routeManager) Add(ips []net.IP, ttl time.Duration, now time.Time) {
	if m == nil || m.dev == "" {
		return
	}
	if ttl < routeMinTTL {
		ttl = routeMinTTL
	}
	if ttl > routeMaxTTL {
		ttl = routeMaxTTL
	}
	expiry := now.Add(ttl)

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		key := v4.String()
		if _, ok := m.routes[key]; ok {
			m.routes[key] = expiry
			continue
		}
		if len(m.routes) >= maxSplitRoutes && len(m.order) > 0 {
			oldest := m.order[0]
			m.order = m.order[1:]
			delete(m.routes, oldest)
			_ = m.run("route", "del", oldest+"/32", "dev", m.dev)
		}
		if err := m.run("route", "replace", key+"/32", "dev", m.dev); err != nil {
			debugf("split: route add %s failed: %v", key, err)
			continue
		}
		m.routes[key] = expiry
		m.order = append(m.order, key)
		debugf("split: routed %s via %s until %s", key, m.dev, expiry.Format(time.RFC3339))
	}
}

func (m *routeManager) Cleanup(now time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.order[:0]
	for _, key := range m.order {
		expiry, ok := m.routes[key]
		if !ok {
			continue
		}
		if now.After(expiry) {
			_ = m.run("route", "del", key+"/32", "dev", m.dev)
			delete(m.routes, key)
			continue
		}
		kept = append(kept, key)
	}
	m.order = kept
}

// Clear removes every route this manager added, for a network change.
func (m *routeManager) Clear() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, key := range m.order {
		_ = m.run("route", "del", key+"/32", "dev", m.dev)
	}
	m.routes = map[string]time.Time{}
	m.order = nil
}

func (m *routeManager) Count() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.routes)
}
