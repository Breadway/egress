package egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"egress/internal/core"
	"egress/internal/logx"
	"egress/internal/wgtunnel"
)

// cmdExit serves or uses a peer exit. Serving is the side that carries another
// device's blocked traffic; using is handled by the supervisor's peer exit
// poller and the peer-exit toggle.
func cmdExit(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: egress exit serve [flags]")
	}
	switch args[0] {
	case "serve":
		return cmdExitServe(args[1:])
	default:
		return fmt.Errorf("unknown exit action %q; use serve", args[0])
	}
}

func cmdExitServe(args []string) error {
	if runtime.GOOS != "linux" {
		return errors.New("serving a peer exit is Linux only for now; this platform can use one")
	}
	fs := newFlagSet("exit serve")
	derpMode := fs.Bool("derp", false, "serve through DERP so the exit can sit behind CGNAT")
	port := fs.Int("port", 7443, "TCP port the exit relay listens on")
	path := fs.String("path", "/peer-exit", "HTTPS path the relay answers on")
	public := fs.String("public-endpoint", "", "host:port other devices should dial; derived from the tunnel endpoint when empty")
	dev := fs.String("dev", core.WGInterface, "WireGuard interface to serve from")
	debug := fs.Bool("debug", false, "trace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))

	self := devicePubkey()
	if self == "" {
		return errors.New("this device has no identity, so it cannot offer an exit")
	}
	wgPort, err := wgListenPort(*dev)
	if err != nil {
		return err
	}
	wan, err := defaultInterface()
	if err != nil {
		return err
	}
	if err := ensureExitNAT(*dev, wan); err != nil {
		return fmt.Errorf("nat: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	transport := "tls"
	endpoint := ""
	var relay *derpTransport
	var srv *http.Server
	if *derpMode {
		transport = "derp"
		relay, err = newDERPTransport(appLogger())
		if err != nil {
			return fmt.Errorf("relay identity: %w", err)
		}
		// Publish the relay key before announcing the exit: the server rejects
		// a DERP exit whose device has no relay key yet.
		if err := announceDerpKey(ctx, relay.PublicKey()); err != nil {
			appLogger().Printf("exit: publish relay key: %v", err)
		}
		go relay.Run(ctx)
		appLogger().Printf("exit: serving through DERP, forwarding to 127.0.0.1:%d", wgPort)
	} else {
		endpoint = strings.TrimSpace(*public)
		if endpoint == "" {
			endpoint, err = ownPublicEndpoint(*port)
			if err != nil {
				return err
			}
		}
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return fmt.Errorf("public endpoint %q: %w", endpoint, err)
		}
		cert, cerr := selfSignedCert()
		if cerr != nil {
			return fmt.Errorf("certificate: %w", cerr)
		}
		target := fmt.Sprintf("127.0.0.1:%d", wgPort)
		listener, lerr := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if lerr != nil {
			return fmt.Errorf("listen on %d: %w", *port, lerr)
		}
		tlsListener := tls.NewListener(listener, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
		srv = &http.Server{Handler: wgtunnel.Handler(target, *path)}
		go func() {
			if serr := srv.Serve(tlsListener); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
				appLogger().Printf("exit: relay stopped: %v", serr)
			}
		}()
		appLogger().Printf("exit: serving on :%d%s, forwarding to %s", *port, *path, target)
	}
	if err := announceSelfExit(context.Background(), transport, endpoint, *path); err != nil {
		appLogger().Printf("exit: announce: %v", err)
	}

	active := map[string]exitClient{}
	links := map[string]*activeExitLink{}
	var slots *exitSlotManager
	if *derpMode {
		slots = newExitSlotManager(ctx, appLogger())
	}
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	announce := time.NewTicker(4 * time.Minute)
	defer announce.Stop()
	for {
		if err := reconcileExitClients(ctx, *dev, active, relay, slots, wgPort, links, *derpMode); err != nil {
			appLogger().Printf("exit: clients: %v", err)
		}
		select {
		case <-ctx.Done():
			for pubkey := range active {
				_ = logx.RunLogged("wg", "set", *dev, "peer", pubkey, "remove")
			}
			for _, cur := range links {
				cur.link.Close()
			}
			if slots != nil {
				slots.close()
			}
			_ = withdrawSelfExit(context.Background())
			if srv != nil {
				_ = srv.Close()
			}
			appLogger().Printf("exit: stopped")
			return nil
		case <-announce.C:
			if err := announceSelfExit(ctx, transport, endpoint, *path); err != nil {
				appLogger().Printf("exit: announce: %v", err)
			}
		case <-tick.C:
		}
	}
}

type exitClient struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	IP         string `json:"ip"`
	PubKey     string `json:"pubkey"`
	DerpPubKey string `json:"derp_pubkey"`
}

// activeExitLink records which relay transport carries a client's UDP link.
// A client starts on the exit's base identity and moves to its own slot.
type activeExitLink struct {
	link      *derpLink
	transport *derpTransport
}

// reconcileExitClients adds a WireGuard peer for every device that chose this
// exit, and removes peers for devices that stopped. In DERP mode each client
// gets a slot identity and its own relay connection, so one client's traffic
// does not limit another's.
func reconcileExitClients(ctx context.Context, dev string, active map[string]exitClient, relay *derpTransport, slots *exitSlotManager, wgPort int, links map[string]*activeExitLink, derpMode bool) error {
	var out struct {
		Clients []exitClient `json:"clients"`
	}
	if err := peerAPI(context.Background(), http.MethodGet, "/api/exit/clients", nil, &out); err != nil {
		return err
	}
	want := map[string]exitClient{}
	for _, c := range out.Clients {
		if c.IP == "" || c.PubKey == "" {
			continue
		}
		want[c.PubKey] = c
	}
	for pubkey, cur := range active {
		if _, ok := want[pubkey]; ok {
			continue
		}
		if err := logx.RunLogged("wg", "set", dev, "peer", pubkey, "remove"); err != nil {
			return err
		}
		if runtime.GOOS == "linux" {
			_ = logx.RunLogged("ip", "route", "del", cur.IP+"/32", "dev", dev)
		}
		if link := links[pubkey]; link != nil {
			link.link.Close()
			delete(links, pubkey)
		}
		if slots != nil {
			slots.remove(cur.ID)
		}
		delete(active, pubkey)
	}
	for pubkey, c := range want {
		if _, ok := active[pubkey]; !ok {
			if err := logx.RunLogged("wg", "set", dev, "peer", pubkey, "allowed-ips", c.IP+"/32"); err != nil {
				return fmt.Errorf("add %s (%s): %w", c.Label, c.IP, err)
			}
			// The exit's own route must point the client's return traffic at
			// this interface, especially when it is not the one that owns the
			// tunnel subnet.
			if runtime.GOOS == "linux" {
				if err := logx.RunLogged("ip", "route", "replace", c.IP+"/32", "dev", dev); err != nil {
					return fmt.Errorf("route %s via %s: %w", c.IP, dev, err)
				}
			}
			active[pubkey] = c
			appLogger().Printf("exit: carrying traffic for %s (%s)", c.Label, c.IP)
		}
		if !derpMode {
			continue
		}
		wantTransport := relay
		if slots != nil {
			slot, serr := slots.ensure(c.ID)
			if serr != nil {
				appLogger().Printf("exit: slot for %s: %v", c.Label, serr)
			} else {
				wantTransport = slot.transport
			}
		}
		if wantTransport == nil {
			continue
		}
		if cur := links[pubkey]; cur != nil {
			if cur.transport == wantTransport {
				continue
			}
			// The slot was just created; move the link to its own identity.
			cur.link.Close()
		}
		key, err := decodeKey(c.DerpPubKey)
		if err != nil {
			appLogger().Printf("exit: %s has no usable relay key: %v", c.Label, err)
			continue
		}
		link, err := wantTransport.AttachDial(key, fmt.Sprintf("127.0.0.1:%d", wgPort))
		if err != nil {
			return fmt.Errorf("relay link for %s: %w", c.Label, err)
		}
		links[pubkey] = &activeExitLink{link: link, transport: wantTransport}
		appLogger().Printf("exit: relaying for %s over DERP", c.Label)
	}
	if slots != nil {
		slots.announce(ctx)
	}
	return nil
}

func announceSelfExit(ctx context.Context, transport, endpoint, path string) error {
	body, _ := json.Marshal(struct {
		Transport string `json:"transport"`
		Endpoint  string `json:"endpoint"`
		Path      string `json:"path"`
	}{Transport: transport, Endpoint: endpoint, Path: path})
	return peerAPI(ctx, http.MethodPost, "/api/exit/announce", body, nil)
}

func withdrawSelfExit(ctx context.Context) error {
	return peerAPI(ctx, http.MethodDelete, "/api/exit/announce", nil, nil)
}

// ownPublicEndpoint uses the endpoint Aegis observes for this device, with the
// relay port in place of the WireGuard port. A relayed device has no public
// address here, so it has to be told one explicitly.
func ownPublicEndpoint(port int) (string, error) {
	var out struct {
		Peers []struct {
			PubKey   string `json:"pubkey"`
			Endpoint string `json:"endpoint"`
		} `json:"peers"`
	}
	if err := peerAPI(context.Background(), http.MethodGet, "/api/peers", nil, &out); err != nil {
		return "", err
	}
	self := devicePubkey()
	for _, p := range out.Peers {
		if p.PubKey != self || p.Endpoint == "" {
			continue
		}
		host, _, err := net.SplitHostPort(p.Endpoint)
		if err != nil {
			continue
		}
		if host == "127.0.0.1" || host == "::1" {
			return "", errors.New("this device reaches Aegis through the relay, so it has no public address; pass --public-endpoint host:port")
		}
		return net.JoinHostPort(host, fmt.Sprint(port)), nil
	}
	return "", errors.New("this device has no observed endpoint yet; pass --public-endpoint host:port")
}

func wgListenPort(dev string) (int, error) {
	out, err := exec.Command("wg", "show", dev, "listen-port").Output()
	if err != nil {
		return 0, fmt.Errorf("read %s listen port: %w", dev, err)
	}
	var port int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &port); err != nil || port == 0 {
		return 0, fmt.Errorf("%s has no listening port", dev)
	}
	return port, nil
}

func defaultInterface() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", errors.New("no default route to carry exit traffic")
}

// ensureExitNAT installs the masquerade rule that lets a carried client reach
// the internet with the exit's address. It is idempotent; the rule is left in
// place when the process exits, because removing it would drop established
// flows the moment the operator restarts the server.
func ensureExitNAT(dev, wan string) error {
	if err := logx.RunLogged("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	rule := []string{
		"-t", "nat", "-C", "POSTROUTING",
		"-s", core.TunnelSubnet, "-o", wan, "-j", "MASQUERADE",
	}
	if err := logx.RunLogged("iptables", rule...); err != nil {
		add := append([]string{"-t", "nat", "-I", "POSTROUTING", "1"}, rule[4:]...)
		if err := logx.RunLogged("iptables", add...); err != nil {
			return err
		}
	}
	forward := []string{"-C", "FORWARD", "-s", core.TunnelSubnet, "-o", wan, "-j", "ACCEPT"}
	if err := logx.RunLogged("iptables", forward...); err != nil {
		add := append([]string{"-I", "FORWARD", "1"}, forward[2:]...)
		if err := logx.RunLogged("iptables", add...); err != nil {
			return err
		}
	}
	return nil
}

// selfSignedCert is enough because WireGuard authenticates the peer. The
// client accepts an untrusted certificate and says so in its log.
func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "egress peer exit"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
