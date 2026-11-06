package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

// dohResolver is both the DoH client and the local plain-DNS server on
// 127.0.0.1:7103. Queries arrive over UDP or TCP, go out as RFC 8484 POSTs, and
// the answers come back untouched, so EDNS, DNSSEC and large responses all
// behave the same way they do upstream.
//
// The bootstrap is in-process: dns.breadway.dev is resolved by dialling the
// network gateway directly, never the system resolver. That is what makes the
// DoH client independent of whatever DNS the system is currently using, so it
// cannot deadlock against its own listener, and no per-domain routing rule is
// needed.
type dohResolver struct {
	url        string
	listenAddr string

	mu      sync.RWMutex
	host    string
	gateway string
	addrs   []string

	client *http.Client
	log    *log.Logger
	// lookup swaps in tests: production is exchange, tests echo canned
	// answers so TCP/UDP framing is covered without network.
	lookup func(context.Context, []byte) ([]byte, error)
}

func newDoHResolver(gateway string, logger *log.Logger) *dohResolver {
	r := &dohResolver{
		url:        dohURL,
		listenAddr: dohListenAddr,
		host:       dohHost,
		gateway:    gateway,
		// Seed with the known address so the very first query works even if the
		// gateway resolver is unavailable or slow.
		addrs: []string{aegisIPv4},
		log:   logger,
	}
	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{ServerName: dohHost, MinVersion: tls.VersionTLS12},
		DialContext:           r.dial,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   16,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	r.client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	r.lookup = r.exchange
	return r
}

func (r *dohResolver) SetGateway(gateway string) {
	if gateway == "" {
		return
	}
	r.mu.Lock()
	r.gateway = gateway
	r.mu.Unlock()
}

// CloseIdle drops pooled DoH connections. The supervisor calls it on network
// change so queries do not keep using established connections bound to the
// old interface.
func (r *dohResolver) CloseIdle() {
	r.client.CloseIdleConnections()
}

func (r *dohResolver) targets() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.addrs...)
}

// dial ignores the address the transport asks for and connects to one of the
// resolved Aegis addresses instead. TLS still verifies dns.breadway.dev, so a
// wrong address fails closed.
func (r *dohResolver) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var lastErr error

	for _, ip := range r.targets() {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if err := r.refresh(ctx); err != nil {
		if lastErr == nil {
			lastErr = err
		}
		return nil, lastErr
	}

	for _, ip := range r.targets() {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no address for " + dohHost)
	}
	return nil, lastErr
}

// refresh resolves the DoH host through the gateway resolver only. It is never
// called from refresh itself, so it cannot recurse.
func (r *dohResolver) refresh(ctx context.Context) error {
	r.mu.RLock()
	gateway := r.gateway
	r.mu.RUnlock()

	var resolver *net.Resolver
	if gateway != "" {
		gw := gateway
		resolver = &net.Resolver{
			PreferGo:     true,
			StrictErrors: false,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", net.JoinHostPort(gw, "53"))
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupHost(lookupCtx, r.host)
	if err != nil {
		return err
	}

	v4 := make([]string, 0, len(ips))
	for _, ip := range ips {
		if net.ParseIP(ip).To4() != nil {
			v4 = append(v4, ip)
		}
	}
	if len(v4) == 0 {
		return errors.New("no IPv4 address for " + r.host)
	}

	r.mu.Lock()
	r.addrs = v4
	r.mu.Unlock()
	debugf("bootstrap %s via gateway %q: %v", r.host, gateway, v4)
	return nil
}

func (r *dohResolver) exchange(ctx context.Context, query []byte) ([]byte, error) {
	// Trace how far each lookup gets: TCP connect, TLS handshake, first
	// response byte, or a reused pool connection. On failure the stages say
	// whether the path is dead (no connect), the handshake stalls, or the
	// server never answers. Same log volume as before: one line per failed
	// lookup, nothing on success.
	var stages dohStages
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			stages.reused = info.Reused
		},
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				stages.tcp = true
			}
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				stages.tls = true
			}
		},
		GotFirstResponseByte: func() {
			stages.http = true
		},
	}
	ctx = httptrace.WithClientTrace(ctx, trace)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH lookup failed (%s): %v", stages.describe(), err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH returned %s", resp.Status)
	}
	if len(body) < 12 {
		return nil, errors.New("short DNS response")
	}
	debugf("doh: query %d bytes, answer %d bytes", len(query), len(body))
	return body, nil
}

// dohStages records how far one lookup got, for failure diagnosis.
type dohStages struct {
	reused bool
	tcp    bool
	tls    bool
	http   bool
}

func (s dohStages) describe() string {
	if s.http {
		return "server answered, body failed"
	}
	if s.tls {
		return "TLS done, no response"
	}
	if s.tcp {
		return "TCP connected, TLS stalled"
	}
	if s.reused {
		return "reused connection died"
	}
	return "no TCP connection"
}

func (r *dohResolver) serve(ctx context.Context) error {
	udp, err := net.ListenPacket("udp", r.listenAddr)
	if err != nil {
		return fmt.Errorf("udp %s: %w", r.listenAddr, err)
	}
	tcp, err := net.Listen("tcp", r.listenAddr)
	if err != nil {
		udp.Close()
		return fmt.Errorf("tcp %s: %w", r.listenAddr, err)
	}

	go func() {
		<-ctx.Done()
		udp.Close()
		tcp.Close()
	}()

	go r.serveTCP(tcp)
	r.log.Printf("DoH resolver listening on %s", r.listenAddr)
	r.serveUDP(udp)
	return nil
}

func (r *dohResolver) serveUDP(conn net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func(query []byte, addr net.Addr) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := r.lookup(ctx, query)
			if err != nil {
				r.log.Printf("DoH lookup failed: %v", err)
				return
			}
			if _, err := conn.WriteTo(resp, addr); err != nil {
				r.log.Printf("udp write: %v", err)
			}
		}(query, addr)
	}
}

func (r *dohResolver) serveTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go r.handleTCP(conn)
	}
}

func (r *dohResolver) handleTCP(conn net.Conn) {
	defer conn.Close()
	for {
		conn.SetDeadline(time.Now().Add(30 * time.Second))

		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(header[:]))
		if size == 0 {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, err := r.lookup(ctx, query)
		cancel()
		if err != nil {
			r.log.Printf("DoH lookup failed: %v", err)
			return
		}
		if len(resp) > 65535 {
			return
		}

		var prefix [2]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(len(resp)))
		if _, err := conn.Write(prefix[:]); err != nil {
			return
		}
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}
