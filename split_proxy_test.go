package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPACScript(t *testing.T) {
	script := pacScript("127.0.0.1:1081")
	if !strings.Contains(script, "PROXY 127.0.0.1:1081; DIRECT") {
		t.Fatalf("pac: %s", script)
	}
}

func TestSocksConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var gotTarget string
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var greet [2]byte
		_, _ = io.ReadFull(br, greet[:])
		methods := make([]byte, greet[1])
		_, _ = io.ReadFull(br, methods)
		_, _ = conn.Write([]byte{5, 2})
		var authHead [2]byte
		_, _ = io.ReadFull(br, authHead[:])
		user := make([]byte, authHead[1])
		_, _ = io.ReadFull(br, user)
		var plen [1]byte
		_, _ = io.ReadFull(br, plen[:])
		pass := make([]byte, plen[0])
		_, _ = io.ReadFull(br, pass)
		if string(user) != "u" || string(pass) != "p" {
			_, _ = conn.Write([]byte{1, 1})
			return
		}
		_, _ = conn.Write([]byte{1, 0})
		var head [4]byte
		_, _ = io.ReadFull(br, head[:])
		l := make([]byte, 1)
		_, _ = io.ReadFull(br, l[:])
		name := make([]byte, l[0])
		_, _ = io.ReadFull(br, name)
		var port [2]byte
		_, _ = io.ReadFull(br, port[:])
		gotTarget = net.JoinHostPort(string(name), itoa(int(binary.BigEndian.Uint16(port[:]))))
		_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		_, _ = io.Copy(conn, br)
	}()

	conn, err := socksConnect(context.Background(), ln.Addr().String(), "u", "p", "discord.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if gotTarget != "discord.com:443" {
		t.Fatalf("target: %q", gotTarget)
	}
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("echo: %q %v", buf, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestProxyDecidesAndRecords(t *testing.T) {
	dir := t.TempDir()
	p := newSplitProxy("net", dir, "127.0.0.1:0", "127.0.0.1:1", "u", "p", log.New(testWriter{t}, "", 0))
	calls := 0
	p.probe = func(ctx context.Context, domain string, opts ProbeOptions) ProbeResult {
		calls++
		return ProbeResult{Domain: domain, State: StateBlocked, Evidence: EvidenceTLSStall}
	}
	if got := p.decide(context.Background(), "discord.com"); got != StateBlocked {
		t.Fatalf("state: %s", got)
	}
	if got := p.decide(context.Background(), "discord.com"); got != StateBlocked {
		t.Fatalf("second state: %s", got)
	}
	if calls != 1 {
		t.Fatalf("probe calls: %d (must be cached)", calls)
	}
	loaded, err := LoadProfile(ProfilePathIn(dir, "net"), "net")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State("discord.com", time.Now()) != StateBlocked {
		t.Fatal("profile not persisted")
	}
}

func TestProxyConnectDirect(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	p := newSplitProxy("net", t.TempDir(), "127.0.0.1:0", "127.0.0.1:1", "u", "p", log.New(testWriter{t}, "", 0))
	p.probe = func(ctx context.Context, domain string, opts ProbeOptions) ProbeResult {
		return ProbeResult{Domain: domain, State: StateAllowed}
	}
	srv := httptest.NewServer(p.handler())
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("CONNECT " + echo.Addr().String() + " HTTP/1.1\r\nHost: " + echo.Addr().String() + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("status: %q %v", line, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo: %q %v", buf, err)
	}
}

func TestProxyForwardsPlainHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + r.URL.Path))
	}))
	defer upstream.Close()

	p := newSplitProxy("net", t.TempDir(), "127.0.0.1:0", "127.0.0.1:1", "u", "p", log.New(testWriter{t}, "", 0))
	p.probe = func(ctx context.Context, domain string, opts ProbeOptions) ProbeResult {
		return ProbeResult{Domain: domain, State: StateAllowed}
	}
	proxy := httptest.NewServer(p.handler())
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	// This is the shape of Windows' connectivity probe: a plain http request
	// sent to the proxy as an absolute URL.
	resp, err := client.Get(upstream.URL + "/connecttest.txt")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d (plain http must be forwarded, not 404)", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello /connecttest.txt" {
		t.Fatalf("body: %q", body)
	}
}
