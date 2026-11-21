package guiapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// Run samples the daemon state and turns real transitions into activity. It
// does not poll the network or change anything; every source is a cheap
// snapshot of state another loop already owns.
func (s *Server) Run(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	s.sample()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.sample()
		}
	}
}

func (s *Server) sample() {
	st := s.src.Status()
	c := s.src.Circle()
	p := s.src.Protection()

	s.mu.Lock()
	first := s.prev.status.Version == ""
	if st.Connected && (first || !s.prev.status.Connected) {
		s.since = time.Now()
	}
	if !st.Connected {
		s.since = time.Time{}
	}
	added := s.diffLocked(st, c, p, first)
	if added > 0 {
		s.saveActivityLocked()
	}
	s.prev = snapshot{status: st, circle: c, sites: siteMap(p.Sites)}
	s.mu.Unlock()

	if added > 0 {
		s.publish()
	}
}

func siteMap(sites []Site) map[string]Site {
	out := make(map[string]Site, len(sites))
	for _, site := range sites {
		out[site.Domain] = site
	}
	return out
}

// diffLocked produces at most maxPerSample rows so a network that suddenly
// unblocks dozens of sites does not bury the timeline.
func (s *Server) diffLocked(st Status, c Circle, p Protection, first bool) int {
	now := time.Now()
	added := 0
	push := func(at time.Time, kind, title, detail string) {
		if added >= maxPerSample {
			return
		}
		if at.IsZero() {
			at = now
		}
		// Flapping exit or peer state can produce the same row twice in a
		// minute. Keep the timeline readable by collapsing that.
		for i := len(s.events) - 1; i >= 0 && i >= len(s.events)-40; i-- {
			if s.events[i].Title == title && at.Sub(s.events[i].Time) < 2*time.Minute {
				return
			}
		}
		s.events = append(s.events, Event{Time: at, Kind: kind, Title: title, Detail: detail})
		added++
	}

	if first {
		// Seed with the real current picture so a fresh daemon restart does
		// not present an empty Activity screen. Site times come from the last
		// probe, not the moment the GUI opened. A ring restored from disk is
		// already history, so only seed when it is empty.
		if len(s.events) == 0 {
			if st.Connected {
				push(now, "connection", "Protection is on", "egress is carrying blocked sites for you")
			} else {
				push(now, "connection", "Protection is paused", "your normal connection is in use")
			}
			seed := append([]Site(nil), p.Sites...)
			sort.Slice(seed, func(i, j int) bool { return seed[i].At > seed[j].At })
			for _, site := range seed {
				if site.Retry {
					continue
				}
				at, _ := time.Parse(time.RFC3339, site.At)
				push(at, "protection", "Unblocked "+site.Domain, "via "+site.Label)
			}
		}
	} else {
		switch {
		case st.Connected && !s.prev.status.Connected:
			push(now, "connection", "Protection is on", "blocked sites are being unblocked again")
		case !st.Connected && s.prev.status.Connected:
			push(now, "connection", "Protection is paused", "your normal connection is back")
		}
		if st.Connected && s.prev.status.Connected && st.Path != s.prev.status.Path {
			switch st.Path {
			case "cloud":
				push(now, "connection", "Switched to the cloud relay", "a direct path was not available")
			case "direct":
				push(now, "connection", "Back on a direct path", "faster than the relay")
			}
		}
		if st.Connected && st.Exit != "" && st.Exit != s.prev.status.Exit {
			push(now, "friend", st.Exit+" is now helping with your connection", "relayed through their internet")
		}

		before := map[string]Person{}
		for _, person := range s.prev.circle.People {
			before[person.ID] = person
		}
		for _, person := range c.People {
			if person.Self {
				continue
			}
			old, known := before[person.ID]
			if known && old.Transport == person.Transport && old.Online == person.Online {
				continue
			}
			switch {
			case !person.Online:
				if known && old.Online {
					push(now, "friend", person.Name+" went offline", "their device is not reachable")
				}
			case person.Transport == "direct":
				push(now, "connection", "Found a direct link to "+person.Name, "faster path without a relay")
			case person.Transport == "relay":
				if person.Sharing {
					push(now, "friend", person.Name+" is now helping with your connection", "relayed through their internet")
				} else {
					push(now, "friend", person.Name+" joined over the relay", "their network needs the relay")
				}
			}
		}

		for _, site := range p.Sites {
			old, known := s.prev.sites[site.Domain]
			if known && old.Retry == site.Retry {
				continue
			}
			if site.Retry {
				push(now, "protection", "Could not reach "+site.Domain, "a retry is queued")
			} else {
				push(now, "protection", "Unblocked "+site.Domain, "via "+site.Label)
			}
		}
	}

	if len(s.events) > maxEvents {
		s.events = s.events[len(s.events)-maxEvents:]
	}
	return added
}

// publish wakes every SSE subscriber with the newest batch. The channel only
// carries a signal; clients read the ring through Activity.
func (s *Server) publish() {
	s.mu.Lock()
	var latest Event
	if len(s.events) > 0 {
		latest = s.events[len(s.events)-1]
	}
	s.mu.Unlock()
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- latest:
		default:
		}
	}
}

// Events streams status every two seconds and activity rows as they appear.
func (s *Server) Events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method", "GET only")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "stream", "streaming is not available")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ch := make(chan Event, 16)
	s.subMu.Lock()
	s.subs[ch] = struct{}{}
	s.subMu.Unlock()
	defer func() {
		s.subMu.Lock()
		delete(s.subs, ch)
		s.subMu.Unlock()
	}()

	send := func(event string, v any) bool {
		data, err := json.Marshal(v)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !send("status", s.status()) {
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			if !send("status", s.status()) {
				return
			}
		case event := <-ch:
			if !send("activity", event) {
				return
			}
		}
	}
}
