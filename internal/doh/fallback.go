package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Public DoH fallbacks.
//
// When the Aegis resolver is blocked or down, the machine loses DNS entirely,
// which looks like the network died. A public resolver keeps lookups working at
// the cost of privacy: whoever runs it sees the queries, so it is a fallback,
// not a replacement, and the log says when it is in use.
//
// Each entry carries an address to dial directly, so the fallback does not
// depend on the system resolver working, which is the whole point.

const fallbackCooldown = 2 * time.Minute

type fallback struct {
	url    string
	host   string
	boots  []string
	client *http.Client

	fails atomic.Int32
	// until is a unix-nano deadline; while it is in the future this fallback is
	// skipped so a dead server costs one timeout, not one per query.
	until atomic.Int64
}

// parseFallbacks turns "host=ip,host=ip" into entries. A malformed entry is
// skipped rather than failing the resolver.
func parseFallbacks(spec string) []*fallback {
	var out []*fallback
	for _, item := range strings.Split(spec, ",") {
		host, ip, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || host == "" || ip == "" {
			continue
		}
		fb := &fallback{
			url:   "https://" + host + "/dns-query",
			host:  host,
			boots: []string{ip},
		}
		fb.client = fb.newClient()
		out = append(out, fb)
	}
	return out
}

func (f *fallback) newClient() *http.Client {
	boots := f.boots
	host := f.host
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 8,
		TLSHandshakeTimeout: 6 * time.Second,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 4 * time.Second}
			var lastErr error
			for _, ip := range boots {
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second}
}

// ask posts one query to this fallback.
func (f *fallback) ask(ctx context.Context, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", f.host, resp.Status)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(http.MaxBytesReader(nil, resp.Body, 64<<10)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// exchangeFallbacks tries each public resolver in order, skipping any that
// failed recently.
func (r *Resolver) exchangeFallbacks(ctx context.Context, query []byte) ([]byte, error) {
	now := time.Now().UnixNano()
	for _, fb := range r.fallbacks {
		if until := fb.until.Load(); until > now {
			continue
		}
		body, err := fb.ask(ctx, query)
		if err == nil {
			if fb.fails.Swap(0) > 0 {
				r.log.Printf("doh: fallback %s recovered", fb.host)
			}
			r.log.Printf("doh: answered through fallback %s", fb.host)
			return body, nil
		}
		fb.fails.Add(1)
		fb.until.Store(time.Now().Add(fallbackCooldown).UnixNano())
		r.log.Printf("doh: fallback %s failed, skipping it for %s: %v", fb.host, fallbackCooldown, err)
	}
	return nil, fmt.Errorf("no DoH upstream answered")
}
