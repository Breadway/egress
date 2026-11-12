package main

import (
	"encoding/binary"
	"net"
	"time"
)

// dnsQueryName returns the first question name from a DNS query, lowercased.
// Empty on malformed input, which the resolver then ignores.
func dnsQueryName(query []byte) string {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) == 0 {
		return ""
	}
	name, _, ok := dnsNameAt(query, 12)
	if !ok {
		return ""
	}
	return NormalizeDomain(name)
}

// dnsNameAt decodes a possibly compressed name starting at off and returns the
// name plus the offset just past the name in the original position.
func dnsNameAt(msg []byte, off int) (string, int, bool) {
	var name []byte
	next := off
	jumped := false
	for steps := 0; steps < 64; steps++ {
		if off >= len(msg) {
			return "", 0, false
		}
		length := int(msg[off])
		switch {
		case length == 0:
			off++
			if !jumped {
				next = off
			}
			return string(name), next, true
		case length&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if !jumped {
				next = off + 2
				jumped = true
			}
			if ptr >= len(msg) {
				return "", 0, false
			}
			off = ptr
		case length&0xc0 != 0:
			return "", 0, false
		default:
			if off+1+length > len(msg) {
				return "", 0, false
			}
			if len(name) > 0 {
				name = append(name, '.')
			}
			name = append(name, msg[off+1:off+1+length]...)
			off += 1 + length
		}
	}
	return "", 0, false
}

// dnsAnswerIPv4 extracts A records from a response and the smallest TTL among
// them. A response with no A records returns nil and a zero TTL.
func dnsAnswerIPv4(resp []byte) ([]net.IP, time.Duration) {
	if len(resp) < 12 {
		return nil, 0
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, ok := dnsNameAt(resp, off)
		if !ok || next+4 > len(resp) {
			return nil, 0
		}
		off = next + 4
	}

	var ips []net.IP
	var minTTL uint32
	for i := 0; i < an; i++ {
		_, next, ok := dnsNameAt(resp, off)
		if !ok || next+10 > len(resp) {
			break
		}
		rrType := binary.BigEndian.Uint16(resp[next : next+2])
		ttl := binary.BigEndian.Uint32(resp[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(resp[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdlen > len(resp) {
			break
		}
		if rrType == 1 && rdlen == 4 {
			ip := make(net.IP, 4)
			copy(ip, resp[rdata:rdata+4])
			ips = append(ips, ip)
			if minTTL == 0 || ttl < minTTL {
				minTTL = ttl
			}
		}
		off = rdata + rdlen
	}
	if len(ips) == 0 {
		return nil, 0
	}
	return ips, time.Duration(minTTL) * time.Second
}
