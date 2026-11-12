package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	socksVersion = 5
	authVersion  = 1

	methodUserPass = 0x02
	methodNone     = 0x00
	methodReject   = 0xff

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repNotAllowed       = 0x02
	repNetworkUnreach   = 0x03
	repHostUnreach      = 0x04
	repConnectionRefuse = 0x05
	repCommandNotSup    = 0x07
	repAddrNotSup       = 0x08
)

// relay is the SOCKS5 server. The dial, resolve and guard hooks exist so the
// protocol can be tested without opening real destinations; production leaves
// them at the defaults below.
type relay struct {
	users   map[string]string
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	resolve func(ctx context.Context, host string) ([]net.IP, error)
	guard   func(net.IP) bool
	idle    time.Duration
}

func newRelay(users map[string]string, idle time.Duration) *relay {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &relay{
		users: users,
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		resolve: func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			return addrs, err
		},
		guard: blockedDestination,
		idle:  idle,
	}
}

func (r *relay) handle(conn net.Conn) {
	defer conn.Close()
	if r.idle > 0 {
		_ = conn.SetDeadline(time.Now().Add(r.idle))
	}
	br := bufio.NewReader(conn)
	if err := r.negotiate(conn, br); err != nil {
		return
	}
	target, reply, err := r.readRequest(br)
	if err != nil || reply != repSuccess {
		writeReply(conn, reply)
		return
	}
	remote, err := r.connect(target)
	if err != nil {
		writeReply(conn, replyForDialError(err))
		return
	}
	defer remote.Close()
	if err := writeReply(conn, repSuccess); err != nil {
		return
	}
	// The handshake is done; drop the idle deadline so a long download is
	// not cut off.
	_ = conn.SetDeadline(time.Time{})
	splice(conn, br, remote)
}

func (r *relay) negotiate(conn net.Conn, br *bufio.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil || header[0] != socksVersion {
		return errors.New("bad greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	haveUserPass := false
	for _, m := range methods {
		if m == methodUserPass {
			haveUserPass = true
		}
	}
	if !haveUserPass || len(r.users) == 0 {
		_, _ = conn.Write([]byte{socksVersion, methodReject})
		return errors.New("no acceptable auth method")
	}
	if _, err := conn.Write([]byte{socksVersion, methodUserPass}); err != nil {
		return err
	}
	return r.authenticate(conn, br)
}

func (r *relay) authenticate(conn net.Conn, br *bufio.Reader) error {
	var head [2]byte
	if _, err := io.ReadFull(br, head[:]); err != nil || head[0] != authVersion {
		return errors.New("bad auth header")
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, user); err != nil {
		return err
	}
	var plen [1]byte
	if _, err := io.ReadFull(br, plen[:]); err != nil {
		return err
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(br, pass); err != nil {
		return err
	}
	want, ok := r.users[string(user)]
	valid := ok && subtle.ConstantTimeCompare([]byte(want), pass) == 1
	if !valid {
		_, _ = conn.Write([]byte{authVersion, 0x01})
		return errors.New("auth failed")
	}
	_, err := conn.Write([]byte{authVersion, 0x00})
	return err
}

// readRequest parses a CONNECT request. On protocol errors it returns the
// reply code the client should get.
func (r *relay) readRequest(br *bufio.Reader) (string, byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return "", repGeneralFailure, err
	}
	if head[0] != socksVersion {
		return "", repGeneralFailure, errors.New("bad version")
	}
	if head[1] != cmdConnect {
		return "", repCommandNotSup, errors.New("only CONNECT is supported")
	}
	var host string
	switch head[3] {
	case atypIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(br, raw[:]); err != nil {
			return "", repGeneralFailure, err
		}
		host = net.IP(raw[:]).String()
	case atypIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(br, raw[:]); err != nil {
			return "", repGeneralFailure, err
		}
		host = net.IP(raw[:]).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return "", repGeneralFailure, err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, name); err != nil {
			return "", repGeneralFailure, err
		}
		host = string(name)
	default:
		return "", repAddrNotSup, errors.New("unsupported address type")
	}
	var portRaw [2]byte
	if _, err := io.ReadFull(br, portRaw[:]); err != nil {
		return "", repGeneralFailure, err
	}
	port := int(binary.BigEndian.Uint16(portRaw[:]))
	if port == 0 {
		return "", repNotAllowed, errors.New("port zero")
	}
	if host == "" {
		return "", repHostUnreach, errors.New("empty host")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), repSuccess, nil
}

func (r *relay) connect(target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	ips, err := r.resolve(context.Background(), host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		if r.guard(ip) {
			lastErr = errors.New("destination is not allowed")
			continue
		}
		conn, err := r.dial(context.Background(), "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no usable address")
	}
	return nil, lastErr
}

func replyForDialError(err error) byte {
	var netErr net.Error
	switch {
	case errors.As(err, &netErr) && netErr.Timeout():
		return repHostUnreach
	case strings.Contains(err.Error(), "not allowed"):
		return repNotAllowed
	case strings.Contains(err.Error(), "refused"):
		return repConnectionRefuse
	case strings.Contains(err.Error(), "unreachable"):
		return repNetworkUnreach
	default:
		return repGeneralFailure
	}
}

func writeReply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{socksVersion, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// splice copies both directions until either side closes, then half-closes the
// other. br may already hold buffered client bytes, so it is used instead of
// the raw connection for the client-to-remote direction.
func splice(conn net.Conn, br *bufio.Reader, remote net.Conn) {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(remote, br)
		if tcp, ok := remote.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(conn, remote)
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-done
}

// blockedDestination keeps the relay from reaching loopback, private networks
// and link-local addresses. Without this an authenticated client could use
// Aegis as a bounce into its own services or the tailnet.
func blockedDestination(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 carrier-grade NAT, which includes Tailscale's range.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
		// 198.18.0.0/15 benchmarking range.
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return true
		}
	}
	return false
}
