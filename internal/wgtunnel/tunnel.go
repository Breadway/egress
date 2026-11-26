package wgtunnel

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"egress/internal/core"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults match what the previous tunneler exposed to the WireGuard service:
// the interface dials 127.0.0.1:7108 and the relay forwards to the WireGuard
// listener on the other side.
const (
	DefaultLocal      = "127.0.0.1:7108"
	DefaultHost       = "dns.breadway.dev"
	DefaultPort       = "443"
	DefaultPath       = "/wgt/egress"
	DefaultDoH        = "127.0.0.1:7103"
	DefaultServerAddr = "127.0.0.1:7105"
)

// Options are the tunnel's endpoints. Tests use them to point at a local
// server; production uses the defaults.
type Options struct {
	Local string
	Host  string
	Port  string
	Path  string
	DoH   string
	// Fallback is a known address for Host, used when the local DoH listener
	// cannot answer. The control relay must not depend on the resolver it
	// feeds, so the default host falls back to the seeded Aegis address.
	Fallback string
	// ResolveTimeout bounds one DoH lookup. Tests shorten it.
	ResolveTimeout time.Duration
	// Plain disables TLS. It exists so tests can run against a local server
	// without certificates; production never sets it.
	Plain bool
}

func (o Options) withDefaults() Options {
	if o.Local == "" {
		o.Local = DefaultLocal
	}
	if o.Host == "" {
		o.Host = DefaultHost
	}
	if o.Port == "" {
		o.Port = DefaultPort
	}
	if o.Path == "" {
		o.Path = DefaultPath
	}
	if o.DoH == "" {
		o.DoH = DefaultDoH
	}
	if o.Fallback == "" && o.Host == DefaultHost {
		o.Fallback = core.AegisIPv4
	}
	if o.ResolveTimeout <= 0 {
		o.ResolveTimeout = 8 * time.Second
	}
	return o
}

// Tunnel keeps a UDP socket bound for the WireGuard endpoint and carries its
// datagrams over one upgraded TLS connection. It reconnects on its own; while
// it is down WireGuard retransmits, so nothing has to be buffered beyond a
// small queue.
type Tunnel struct {
	opts Options
	log  *log.Logger

	mu      sync.Mutex
	conn    *net.UDPConn
	cancel  context.CancelFunc
	running bool
	out     chan []byte

	peer       atomic.Value // *net.UDPAddr
	downgraded atomic.Bool
	connected  atomic.Bool
}

func New(logger *log.Logger) *Tunnel {
	return NewWithOptions(Options{}, logger)
}

func NewWithOptions(opts Options, logger *log.Logger) *Tunnel {
	return &Tunnel{opts: opts.withDefaults(), log: logger}
}

// Ensure binds the local UDP port and keeps the session alive. It is
// idempotent: the supervisor calls it on every tick.
func (t *Tunnel) Ensure(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", t.opts.Local)
	if err != nil {
		return fmt.Errorf("relay address %s: %w", t.opts.Local, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("bind relay %s: %w", t.opts.Local, err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	t.conn = conn
	t.cancel = cancel
	t.running = true
	t.out = make(chan []byte, 64)
	t.log.Printf("relay: listening on %s, carrying WireGuard over %s%s", conn.LocalAddr(), t.opts.Host, t.opts.Path)
	go t.readUDP(runCtx, conn)
	go t.sessionLoop(runCtx, conn)
	return nil
}

// Stop closes the local port and ends the session.
func (t *Tunnel) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	t.running = false
	t.connected.Store(false)
}

// LocalAddr reports the bound address, for tests and diagnostics.
func (t *Tunnel) LocalAddr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		return ""
	}
	return t.conn.LocalAddr().String()
}

// Downgraded reports whether TLS verification failed and the session continued
// without it. WireGuard authenticates the peer, so this is a visibility flag,
// not a failure.
func (t *Tunnel) Downgraded() bool { return t.downgraded.Load() }

// Connected reports whether a session is currently established.
func (t *Tunnel) Connected() bool { return t.connected.Load() }

func (t *Tunnel) readUDP(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, MaxDatagram)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		t.peer.Store(addr)
		payload := append([]byte(nil), buf[:n]...)
		select {
		case t.out <- payload:
		default:
			// Queue full: the session is catching up or down. WireGuard will
			// retransmit, so dropping is correct and cheaper than blocking.
		}
	}
}

func (t *Tunnel) sessionLoop(ctx context.Context, conn *net.UDPConn) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		sess, downgraded, err := t.dial(ctx)
		if err != nil {
			t.log.Printf("relay: connect failed: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		if downgraded {
			t.downgraded.Store(true)
			t.log.Printf("relay: the certificate was not trusted, carrying the tunnel anyway (WireGuard still authenticates the peer)")
		}
		t.connected.Store(true)
		t.log.Printf("relay: connected to %s%s", t.opts.Host, t.opts.Path)

		errCh := make(chan error, 2)
		go func() { errCh <- t.writeSession(ctx, sess.conn) }()
		go func() { errCh <- t.readSession(ctx, sess) }()
		select {
		case <-ctx.Done():
			sess.conn.Close()
			t.connected.Store(false)
			return
		case err := <-errCh:
			sess.conn.Close()
			t.connected.Store(false)
			t.log.Printf("relay: session ended: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

type session struct {
	conn net.Conn
	br   *bufio.Reader
}

func (t *Tunnel) writeSession(ctx context.Context, conn net.Conn) error {
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case payload := <-t.out:
			if err := WriteFrame(conn, payload); err != nil {
				return err
			}
		case <-heartbeat.C:
			// An empty frame keeps the connection alive through NAT and any
			// proxy that drops idle upgrades.
			if err := WriteFrame(conn, nil); err != nil {
				return err
			}
		}
	}
}

func (t *Tunnel) readSession(ctx context.Context, sess session) error {
	buf := make([]byte, MaxDatagram)
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(150 * time.Second))
		payload, err := ReadFrame(sess.br, buf)
		if err != nil {
			return err
		}
		if len(payload) == 0 {
			continue
		}
		peer, _ := t.peer.Load().(*net.UDPAddr)
		if peer == nil {
			continue
		}
		t.mu.Lock()
		conn := t.conn
		t.mu.Unlock()
		if conn == nil {
			return errors.New("local socket closed")
		}
		if _, werr := conn.WriteToUDP(payload, peer); werr != nil {
			return werr
		}
	}
}

func (t *Tunnel) dial(ctx context.Context) (session, bool, error) {
	addr, err := t.resolve(ctx)
	if err != nil {
		return session{}, false, err
	}
	raw, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(addr, t.opts.Port))
	if err != nil {
		return session{}, false, err
	}
	if t.opts.Plain {
		sess, uerr := upgradeConn(raw, t.opts.Host, t.opts.Path)
		if uerr != nil {
			raw.Close()
			return session{}, false, uerr
		}
		return sess, false, nil
	}

	tc := tls.Client(raw, &tls.Config{
		ServerName: t.opts.Host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if herr := tc.HandshakeContext(ctx); herr != nil {
		raw.Close()
		if !isUntrusted(herr) {
			return session{}, false, herr
		}
		// A filtering network that intercepts TLS presents a certificate the
		// system store does not trust. WireGuard authenticates the peer, so the
		// outer certificate only has to look like a session, not vouch for one.
		raw2, derr := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(addr, t.opts.Port))
		if derr != nil {
			return session{}, false, derr
		}
		tc2 := tls.Client(raw2, &tls.Config{
			ServerName:         t.opts.Host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		})
		if herr2 := tc2.HandshakeContext(ctx); herr2 != nil {
			raw2.Close()
			return session{}, false, fmt.Errorf("tls: %v (without verification: %v)", herr, herr2)
		}
		sess, uerr := upgradeConn(tc2, t.opts.Host, t.opts.Path)
		if uerr != nil {
			tc2.Close()
			return session{}, false, uerr
		}
		return sess, true, nil
	}
	sess, uerr := upgradeConn(tc, t.opts.Host, t.opts.Path)
	if uerr != nil {
		tc.Close()
		return session{}, false, uerr
	}
	return sess, false, nil
}

func upgradeConn(conn net.Conn, host, path string) (session, error) {
	if _, err := conn.Write([]byte(UpgradeRequest(host, path))); err != nil {
		return session{}, err
	}
	br := bufio.NewReader(conn)
	if err := ReadUpgradeResponse(br); err != nil {
		return session{}, err
	}
	return session{conn: conn, br: br}, nil
}

func isUntrusted(err error) bool {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &unknown) || errors.As(err, &invalid) ||
		strings.Contains(err.Error(), "certificate")
}

// resolve asks the local DoH listener, not the system resolver. On a filtered
// network the system resolver can return a sinkhole for the relay's own name.
func (t *Tunnel) resolve(ctx context.Context) (string, error) {
	if ip := net.ParseIP(t.opts.Host); ip != nil {
		return ip.String(), nil
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", t.opts.DoH)
		},
	}
	lookup, cancel := context.WithTimeout(ctx, t.opts.ResolveTimeout)
	defer cancel()
	ips, err := r.LookupIPAddr(lookup, t.opts.Host)
	if err != nil {
		if t.opts.Fallback != "" {
			// The relay carries the tunnel that the DoH listener needs to
			// reach the public resolver. Falling back to the seeded control
			// address breaks that deadlock after a tunnel drop.
			t.log.Printf("relay: resolve %s through DoH failed (%v); using known address %s", t.opts.Host, err, t.opts.Fallback)
			return t.opts.Fallback, nil
		}
		return "", fmt.Errorf("resolve %s: %w", t.opts.Host, err)
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return ip.IP.String(), nil
		}
	}
	if len(ips) > 0 {
		return ips[0].IP.String(), nil
	}
	return "", fmt.Errorf("resolve %s: no addresses", t.opts.Host)
}

func sha1Sum(b []byte) []byte {
	sum := sha1.Sum(b)
	return sum[:]
}
