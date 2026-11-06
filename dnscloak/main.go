// Command dnscloak answers selected names with the relay address and forwards
// everything else to the real resolver.
//
// It sits between doh-proxy and dnsproxy on Aegis. All DoH clients ask Aegis
// for DNS, so a name cloaked here is cloaked for every tunnel user without
// rebuilding their clients. The relay address (10.88.0.254) is DNATed on Aegis
// to Hestia:7106, which reads the TLS SNI and connects from its own address.
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const relayIP = "10.88.0.254"

type server struct {
	upstream string
	suffixes []string
}

func main() {
	listen := flag.String("listen", "127.0.0.1:7103", "listen address")
	upstream := flag.String("upstream", "127.0.0.1:7102", "plain DNS upstream")
	suffixFile := flag.String("suffixes", "/etc/dnscloak/suffixes.txt", "domain suffix list")
	flag.Parse()

	suffixes, err := loadSuffixes(*suffixFile)
	if err != nil {
		log.Fatalf("suffixes: %v", err)
	}
	if len(suffixes) == 0 {
		log.Fatal("no suffixes loaded")
	}

	s := &server{upstream: *upstream, suffixes: suffixes}
	udp, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatalf("udp: %v", err)
	}
	tcp, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("tcp: %v", err)
	}
	log.Printf("listening on %s, upstream %s, %d suffixes", *listen, *upstream, len(suffixes))

	go s.serveTCP(tcp)
	s.serveUDP(udp)
}

func loadSuffixes(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if fields := strings.Fields(line); len(fields) > 0 {
			line = fields[0]
		}
		line = strings.ToLower(line)
		line = strings.TrimPrefix(line, "*.")
		line = strings.TrimPrefix(line, ".")
		line = strings.TrimSuffix(line, ".")
		if line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func (s *server) serveUDP(conn net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		go func(query []byte, addr net.Addr) {
			resp := s.handle(query)
			if resp != nil {
				_, _ = conn.WriteTo(resp, addr)
			}
		}(query, addr)
	}
}

func (s *server) serveTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleTCP(conn)
	}
}

func (s *server) handleTCP(conn net.Conn) {
	defer conn.Close()
	for {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp := s.handle(query)
		if resp == nil {
			return
		}
		binary.BigEndian.PutUint16(hdr[:], uint16(len(resp)))
		if _, err := conn.Write(hdr[:]); err != nil {
			return
		}
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

func (s *server) handle(query []byte) []byte {
	name, qtype, questionEnd, ok := parseQuestion(query)
	if !ok {
		return s.forward(query)
	}
	if (qtype == 1 || qtype == 28) && s.matches(name) {
		return synth(query, questionEnd, qtype)
	}
	return s.forward(query)
}

func parseQuestion(query []byte) (string, uint16, int, bool) {
	if len(query) < 12 {
		return "", 0, 0, false
	}
	if binary.BigEndian.Uint16(query[4:6]) != 1 {
		return "", 0, 0, false
	}
	pos := 12
	var labels []string
	for {
		if pos >= len(query) {
			return "", 0, 0, false
		}
		l := int(query[pos])
		pos++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || l > 63 || pos+l > len(query) {
			return "", 0, 0, false
		}
		labels = append(labels, string(query[pos:pos+l]))
		pos += l
	}
	if pos+4 > len(query) {
		return "", 0, 0, false
	}
	qtype := binary.BigEndian.Uint16(query[pos : pos+2])
	if binary.BigEndian.Uint16(query[pos+2:pos+4]) != 1 {
		return "", 0, 0, false
	}
	pos += 4
	return strings.ToLower(strings.Join(labels, ".")), qtype, pos, true
}

func (s *server) matches(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, suffix := range s.suffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

func synth(query []byte, questionEnd int, qtype uint16) []byte {
	resp := make([]byte, 12)
	copy(resp[0:2], query[0:2])
	resp[2] = 0x81 // QR, RD
	resp[3] = 0x80 // RA, NOERROR
	binary.BigEndian.PutUint16(resp[4:6], 1)
	answers := uint16(0)
	if qtype == 1 {
		answers = 1
	}
	binary.BigEndian.PutUint16(resp[6:8], answers)
	resp = append(resp, query[12:questionEnd]...)
	if qtype == 1 {
		resp = append(resp,
			0xC0, 0x0C, // pointer to the question name
			0x00, 0x01, // A
			0x00, 0x01, // IN
			0x00, 0x00, 0x00, 0x3C, // 60s
			0x00, 0x04, // 4 bytes
			10, 88, 0, 254,
		)
	}
	return resp
}

func (s *server) forward(query []byte) []byte {
	resp := s.forwardUDP(query)
	if resp == nil {
		return servfail(query)
	}
	if len(resp) >= 3 && resp[2]&0x02 != 0 {
		if tcp := s.forwardTCP(query); tcp != nil {
			return tcp
		}
	}
	return resp
}

func (s *server) forwardUDP(query []byte) []byte {
	conn, err := net.DialTimeout("udp", s.upstream, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

func (s *server) forwardTCP(query []byte) []byte {
	conn, err := net.DialTimeout("tcp", s.upstream, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return nil
	}
	if _, err := conn.Write(query); err != nil {
		return nil
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil
	}
	return resp
}

func servfail(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, 12)
	copy(resp, query[:12])
	resp[2] = 0x81
	resp[3] = 0x82 // SERVFAIL
	for i := 4; i < 12; i++ {
		resp[i] = 0
	}
	return resp
}
