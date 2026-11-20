// Package wgtunnel carries WireGuard datagrams over an HTTP upgrade to the
// relay, and serves that upgrade on the relay side.
//
// It replaces the Rust tunneler for the UDP leg. The transport is an HTTP
// WebSocket upgrade: browsers and filtering appliances see an ordinary
// WebSocket on 443, while the payload is WireGuard, which authenticates the
// peer end to end. A TLS-intercepting network therefore cannot see or forge
// anything inside it.
package wgtunnel

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

const (
	// MaxDatagram bounds one framed message. WireGuard interfaces stay under
	// 1500 bytes, so this is generous headroom.
	MaxDatagram = 65535

	// WebSocketGUID is the constant from RFC 6455 used to compute the accept
	// value. Both ends only need the upgrade to complete; the bytes after it
	// are our own length-prefixed frames.
	WebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// WriteFrame writes one length-prefixed message.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxDatagram {
		payload = payload[:MaxDatagram]
	}
	var head [2]byte
	head[0] = byte(len(payload) >> 8)
	head[1] = byte(len(payload))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed message into buf. A zero-length message
// is the heartbeat and is returned as an empty slice.
func ReadFrame(r io.Reader, buf []byte) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := int(head[0])<<8 | int(head[1])
	if n == 0 {
		return buf[:0], nil
	}
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	out := buf[:n]
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpgradeRequest is the HTTP request that opens the relay channel.
func UpgradeRequest(host, path string) string {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i * 7) // deterministic is fine: this is not a secret
	}
	return "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n\r\n"
}

// ReadUpgradeResponse checks that the server accepted the upgrade.
func ReadUpgradeResponse(br *bufio.Reader) error {
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, " 101") {
		return fmt.Errorf("relay refused the upgrade: %s", strings.TrimSpace(line))
	}
	for {
		header, herr := br.ReadString('\n')
		if herr != nil {
			return herr
		}
		if header == "\r\n" || header == "\n" {
			return nil
		}
	}
}

// Handler upgrades the connection and forwards datagrams to target.
//
// Only one destination is ever reachable, the WireGuard listener on the relay,
// so there is nothing here a stranger can use as an open proxy. The tunnel
// itself is authenticated by WireGuard.
func Handler(target, prefix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		if !headerHas(r, "Connection", "upgrade") || !headerHas(r, "Upgrade", "websocket") {
			http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "upgrade unsupported", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		log.Printf("wgtunnel: session from %s for %s", r.RemoteAddr, target)
		accept := acceptKey(r.Header.Get("Sec-WebSocket-Key"))
		_, werr := io.WriteString(conn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: "+accept+"\r\n\r\n")
		if werr != nil {
			conn.Close()
			return
		}
		go serve(conn, brw.Reader, target)
	})
}

func headerHas(r *http.Request, name, want string) bool {
	for _, part := range strings.Split(r.Header.Get(name), ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}

func acceptKey(key string) string {
	return base64.StdEncoding.EncodeToString(sha1Sum([]byte(key + WebSocketGUID)))
}

func serve(conn net.Conn, br *bufio.Reader, target string) {
	defer conn.Close()
	udp, err := net.Dial("udp", target)
	if err != nil {
		return
	}
	defer udp.Close()

	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, MaxDatagram)
		for {
			payload, rerr := ReadFrame(br, buf)
			if rerr != nil {
				done <- struct{}{}
				return
			}
			if len(payload) == 0 {
				continue
			}
			if _, werr := udp.Write(payload); werr != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, MaxDatagram)
		for {
			n, rerr := udp.Read(buf)
			if rerr != nil {
				done <- struct{}{}
				return
			}
			if werr := WriteFrame(conn, buf[:n]); werr != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}
