package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// splitProxy is the per-user Windows split client: an HTTP CONNECT proxy that
// decides per destination whether to go direct or through the Aegis relay. It
// also serves the PAC file the browser points at.
//
// Unknown destinations are probed once; the result is stored in the same
// per-network profile the Linux split mode uses, so both paths learn the same
// way.
type splitProxy struct {
	listenAddr string
	relayAddr  string
	user       string
	pass       string
	network    string
	log        *log.Logger

	mu      sync.Mutex
	profile *Profile
	path    string

	probe     func(context.Context, string, ProbeOptions) ProbeResult
	dial      func(context.Context, string, string) (net.Conn, error)
	socksDial func(context.Context, string, string, string, string) (net.Conn, error)

	direct  atomic.Int64
	relayed atomic.Int64
}

func newSplitProxy(network, dir, listen, relay, user, pass string, logger *log.Logger) *splitProxy {
	p := &splitProxy{
		listenAddr: listen,
		relayAddr:  relay,
		user:       user,
		pass:       pass,
		network:    network,
		log:        logger,
	}
	p.path = ProfilePathIn(dir, network)
	profile, err := LoadProfile(p.path, network)
	if err != nil {
		logger.Printf("proxy: could not read %s (%v); starting empty", p.path, err)
		profile = NewProfile(network)
	}
	p.profile = profile
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	p.dial = dialer.DialContext
	p.probe = ProbeDomain
	p.socksDial = socksConnect
	return p
}

func (p *splitProxy) handler() http.Handler {
	// CONNECT requests use authority-form URLs, so a ServeMux would 404 them.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodConnect:
			p.serveConnect(w, r)
		case r.URL.Path == "/proxy.pac":
			p.servePAC(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (p *splitProxy) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              p.listenAddr,
		Handler:           p.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func pacScript(listen string) string {
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  // Every request goes to the local proxy, which decides per destination
  // whether to go direct or through the Aegis relay.
  return "PROXY %s; DIRECT";
}
`, listen)
}

func (p *splitProxy) servePAC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, pacScript(p.listenAddr))
}

func (p *splitProxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "this proxy only supports CONNECT", http.StatusMethodNotAllowed)
		return
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	mode := p.decide(ctx, host)
	var upstream net.Conn
	if mode == StateBlocked {
		upstream, err = p.socksDial(ctx, p.relayAddr, p.user, p.pass, r.Host)
		p.relayed.Add(1)
	} else {
		upstream, err = p.dial(ctx, "tcp", r.Host)
		p.direct.Add(1)
	}
	if err != nil {
		debugf("proxy: %s (%s): %v", r.Host, mode, err)
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	// Bytes the client sent after CONNECT are already buffered.
	if n := buf.Reader.Buffered(); n > 0 {
		if _, err := io.CopyN(upstream, buf, int64(n)); err != nil {
			client.Close()
			upstream.Close()
			return
		}
	}
	pipeConns(client, upstream)
}

// decide returns the state for one destination, probing unknown names once and
// recording the result.
func (p *splitProxy) decide(ctx context.Context, host string) DomainState {
	host = NormalizeDomain(host)
	now := time.Now()
	p.mu.Lock()
	state := p.profile.State(host, now)
	p.mu.Unlock()
	if state != StateUnknown {
		return state
	}

	probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	res := p.probe(probeCtx, host, ProbeOptions{Timeout: probeTimeout})
	cancel()

	p.mu.Lock()
	switch res.State {
	case StateBlocked:
		p.profile.RecordProbe(host, res.Evidence, true, now)
		p.profile.RecordProbe(host, res.Evidence, true, now)
	case StateAllowed:
		p.profile.RecordProbe(host, EvidenceNone, false, now)
	}
	if res.State == StateBlocked || res.State == StateAllowed {
		if err := p.profile.Save(p.path); err != nil {
			p.log.Printf("proxy: save profile: %v", err)
		}
	}
	p.mu.Unlock()

	if res.State == StateBlocked {
		return StateBlocked
	}
	return StateAllowed
}

func (p *splitProxy) stats() (direct, relayed int64) {
	return p.direct.Load(), p.relayed.Load()
}

// pipeConns copies both directions and half-closes as each side finishes.
func pipeConns(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(b, a)
		if tcp, ok := b.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(a, b)
	if tcp, ok := a.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-done
}
