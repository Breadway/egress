// Package derp is a small DERP client.
//
// It speaks the DERP v2 wire protocol directly: an HTTPS upgrade on /derp, one
// sealed ClientInfo frame, then length-prefixed frames carrying opaque
// datagrams addressed by a 32-byte Curve25519 public key. Egress uses it to
// carry WireGuard packets between peers when a direct path cannot be
// established. The relay is reachability only: WireGuard authenticates and
// encrypts everything above it.
//
// A WireGuard key is a valid DERP node key (both are X25519 scalar-multiplied
// public keys of a clamped private key), so the peer public key in the Egress
// registry addresses the relay without a second key exchange.
package derp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	// AppName is the stable application name the relay sees. It must be set:
	// the public relays are shared, and the operator asks consumers to
	// identify themselves.
	AppName = "egress"

	protocolVersion = 2
	keyLen          = 32
	frameHeaderLen  = 5
	maxPacketSize   = 64 << 10
	maxFrameSize    = 1 << 20

	frameServerKey  = 0x01
	frameClientInfo = 0x02
	frameServerInfo = 0x03
	frameSendPacket = 0x04
	frameRecvPacket = 0x05
	frameKeepAlive  = 0x06
	framePing       = 0x12
	framePong       = 0x13
)

// Magic is the greeting prefix a relay sends when it reports its key in a
// frame rather than an HTTP header.
const Magic = "DERP\U0001F511"

// Relay is one relay node to dial.
type Relay struct {
	Host   string
	Port   string
	Region string
	Node   string
}

// Options configure a client connection.
type Options struct {
	Relay   Relay
	Private [32]byte
	Version string
	// RootCAs overrides the system roots. It exists so tests can trust a
	// locally generated relay certificate.
	RootCAs  *x509.CertPool
	OnPacket func(src [32]byte, pkt []byte)
}

// Client is one DERP connection. Send is safe for concurrent use; Close may be
// called from any goroutine.
type Client struct {
	opts      Options
	relay     Relay
	conn      net.Conn
	br        *bufio.Reader
	bw        *bufio.Writer
	serverKey [32]byte
	publicKey [32]byte

	wmu       sync.Mutex
	closeOnce sync.Once
	done      chan struct{}
	err       atomic.Value
	lastRecv  atomic.Int64
}

// Dial connects to a relay, completes the DERP handshake, and starts reading.
// The returned client is already usable; OnPacket runs on the read goroutine,
// so it must not block.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	if opts.Relay.Host == "" {
		return nil, errors.New("no relay host")
	}
	port := opts.Relay.Port
	if port == "" {
		port = "443"
	}
	hostPort := net.JoinHostPort(opts.Relay.Host, port)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 15 * time.Second},
		Config: &tls.Config{
			ServerName: opts.Relay.Host,
			MinVersion: tls.VersionTLS12,
			RootCAs:    opts.RootCAs,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", hostPort, err)
	}
	br := bufio.NewReaderSize(conn, 4096)
	bw := bufio.NewWriterSize(conn, 4096)

	request := "GET /derp HTTP/1.1\r\n" +
		"Host: " + opts.Relay.Host + "\r\n" +
		"Upgrade: DERP\r\n" +
		"Connection: Upgrade\r\n" +
		"User-Agent: " + userAgent(opts.Version) + "\r\n\r\n"
	deadline := time.Now().Add(15 * time.Second)
	_ = conn.SetDeadline(deadline)
	if _, err := bw.WriteString(request); err != nil {
		conn.Close()
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	req := &http.Request{Method: http.MethodGet}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("upgrade refused: %s: %q", resp.Status, strings.TrimSpace(string(body)))
	}

	c := &Client{opts: opts, relay: opts.Relay, conn: conn, br: br, bw: bw, done: make(chan struct{})}
	pub, err := curve25519.X25519(opts.Private[:], curve25519.Basepoint)
	if err != nil {
		conn.Close()
		return nil, err
	}
	copy(c.publicKey[:], pub)

	if keyHex := resp.Header.Get("Derp-Public-Key"); keyHex != "" {
		raw, err := hex.DecodeString(keyHex)
		if err != nil || len(raw) != keyLen {
			conn.Close()
			return nil, fmt.Errorf("bad Derp-Public-Key header")
		}
		copy(c.serverKey[:], raw)
	} else if err := c.readServerKey(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := c.sendClientInfo(); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	go c.readLoop()
	go c.keepAliveLoop()
	return c, nil
}

func userAgent(version string) string {
	if version == "" {
		version = "unknown"
	}
	return AppName + "/" + version
}

// readServerKey handles relays that report their key in a frame instead of the
// upgrade headers.
func (c *Client) readServerKey() error {
	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	t, n, err := readFrameHeader(c.br)
	if err != nil {
		return fmt.Errorf("read server key: %w", err)
	}
	if n < uint32(len(Magic)+keyLen) || t != frameServerKey {
		return errors.New("relay did not send a server key")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return err
	}
	if string(buf[:len(Magic)]) != Magic {
		return errors.New("bad server key greeting")
	}
	copy(c.serverKey[:], buf[len(Magic):len(Magic)+keyLen])
	return nil
}

func (c *Client) sendClientInfo() error {
	info, err := json.Marshal(struct {
		Version     int `json:"version,omitempty"`
		CanAckPings bool
		AppName     string `json:",omitempty"`
	}{Version: protocolVersion, CanAckPings: true, AppName: AppName})
	if err != nil {
		return err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	sealed := box.Seal(nonce[:], info, &nonce, &c.serverKey, &c.opts.Private)
	payload := make([]byte, 0, keyLen+len(sealed))
	payload = append(payload, c.publicKey[:]...)
	payload = append(payload, sealed...)
	return c.writeFrame(frameClientInfo, payload)
}

// PublicKey is this connection's DERP key, which is the Egress peer's
// WireGuard public key.
func (c *Client) PublicKey() [32]byte { return c.publicKey }

// ServerKey is the relay's key, from the upgrade header or greeting.
func (c *Client) ServerKey() [32]byte { return c.serverKey }

// Relay reports the node this connection reached.
func (c *Client) Relay() Relay { return c.relay }

// Send relays one datagram to dst.
func (c *Client) Send(dst [32]byte, pkt []byte) error {
	if len(pkt) > maxPacketSize {
		return fmt.Errorf("packet too big: %d", len(pkt))
	}
	payload := make([]byte, 0, keyLen+len(pkt))
	payload = append(payload, dst[:]...)
	payload = append(payload, pkt...)
	return c.writeFrame(frameSendPacket, payload)
}

// LastRecv reports when the relay last sent anything. The server pings
// regularly, so a stale value means the connection is dead even if writes
// still land in a socket buffer.
func (c *Client) LastRecv() time.Time {
	ns := c.lastRecv.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Done closes when the connection ends.
func (c *Client) Done() <-chan struct{} { return c.done }

// Err reports why the connection ended.
func (c *Client) Err() error {
	if v := c.err.Load(); v != nil {
		return v.(error)
	}
	return nil
}

// Close ends the connection and its read loop.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.conn.Close()
	})
	return nil
}

func (c *Client) readLoop() {
	err := c.readFrames()
	if err != nil {
		c.err.Store(err)
	}
	c.Close()
}

func (c *Client) readFrames() error {
	buf := make([]byte, maxFrameSize+frameHeaderLen)
	for {
		// The relay pings often; a long silence means the path is gone.
		if err := c.conn.SetReadDeadline(time.Now().Add(90 * time.Second)); err != nil {
			return err
		}
		t, n, err := readFrameHeader(c.br)
		if err != nil {
			return err
		}
		if n > maxFrameSize {
			return fmt.Errorf("oversized frame: %d", n)
		}
		payload := buf[:n]
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return err
		}
		c.lastRecv.Store(time.Now().UnixNano())
		switch t {
		case frameRecvPacket:
			if len(payload) < keyLen {
				continue
			}
			var src [32]byte
			copy(src[:], payload[:keyLen])
			if c.opts.OnPacket != nil {
				c.opts.OnPacket(src, payload[keyLen:])
			}
		case framePing:
			if len(payload) == 8 {
				if err := c.writeFrame(framePong, payload); err != nil {
					return err
				}
			}
		case frameServerInfo, frameKeepAlive, framePong:
		}
	}
}

func (c *Client) keepAliveLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if err := c.writeFrame(frameKeepAlive, nil); err != nil {
				c.Close()
				return
			}
		}
	}
}

func (c *Client) writeFrame(t byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	header := [frameHeaderLen]byte{t}
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := c.bw.Write(header[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := c.bw.Write(payload); err != nil {
			return err
		}
	}
	return c.bw.Flush()
}

func readFrameHeader(br *bufio.Reader) (byte, uint32, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return 0, 0, err
	}
	return hdr[0], binary.BigEndian.Uint32(hdr[1:]), nil
}
