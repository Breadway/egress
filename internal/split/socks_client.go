package split

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// socksConnect opens a SOCKS5 CONNECT to target through relay, authenticating
// with the credentials baked into the build. It is the client half of the relay
// in socksrelay/.
func socksConnect(ctx context.Context, relay, user, pass, target string) (net.Conn, error) {
	if user == "" || pass == "" {
		return nil, errors.New("missing relay credentials")
	}
	if len(user) > 255 || len(pass) > 255 {
		return nil, errors.New("relay credentials too long")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("bad port %q", portStr)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", relay)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	// Greeting: SOCKS5, one method, username/password.
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return nil, err
	}
	var two [2]byte
	if _, err := io.ReadFull(br, two[:]); err != nil {
		return nil, err
	}
	if two[0] != 5 || two[1] != 2 {
		return nil, errors.New("relay does not offer username/password auth")
	}

	// RFC 1929 auth.
	auth := []byte{1, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := conn.Write(auth); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(br, two[:]); err != nil {
		return nil, err
	}
	if two[0] != 1 || two[1] != 0 {
		return nil, errors.New("relay rejected the credentials")
	}

	// CONNECT request.
	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			addr = append([]byte{1}, v4...)
		} else {
			addr = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("target host too long")
		}
		addr = append([]byte{3, byte(len(host))}, []byte(host)...)
	}
	addr = append(addr, byte(port>>8), byte(port))
	req := append([]byte{5, 1, 0}, addr...)
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	var head [4]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return nil, err
	}
	if head[0] != 5 || head[1] != 0 {
		return nil, fmt.Errorf("relay replied %d", head[1])
	}
	switch head[3] {
	case 1:
		_, err = io.CopyN(io.Discard, br, 4+2)
	case 4:
		_, err = io.CopyN(io.Discard, br, 16+2)
	case 3:
		var l [1]byte
		if _, rerr := io.ReadFull(br, l[:]); rerr == nil {
			_, err = io.CopyN(io.Discard, br, int64(l[0])+2)
		} else {
			err = rerr
		}
	default:
		err = errors.New("bad bound address type")
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}
