//go:build windows

package egress

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"egress/internal/core"
	"egress/internal/logx"
	"egress/internal/wstunnel"
)

// cmdWGProbe is stage one of moving split mode onto a WireGuard interface that
// rides the WebSocket tunnel. It proves the path end to end without touching
// the split proxy: one peer, one AllowedIPs entry, ping through it.
//
// The SOCKS relay stays exactly as it is. If this fails, nothing regresses.
func cmdWGProbe(args []string) error {
	fs := newFlagSet("wg-probe")
	ip := fs.String("ip", "", "tunnel address assigned to the probe peer")
	allowed := fs.String("allowed", core.AegisTunnelIP+"/32", "AllowedIPs for the probe")
	printKey := fs.Bool("print-key", false, "print the probe public key and exit")
	cleanup := fs.Bool("cleanup", false, "remove the probe tunnel, config and client")
	debug := fs.Bool("debug", false, "trace commands")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))

	plat := newPlatform()
	if err := plat.RequirePrivilege(); err != nil {
		return err
	}

	keyPath := filepath.Join(core.InstallDir(), "wg-probe.key")
	confPath := filepath.Join(core.InstallDir(), "wg0ws-probe.conf")
	service := "wg0ws-probe"

	if *cleanup {
		_ = exec.Command(wireguardExeFor(), "/uninstalltunnelservice", service).Run()
		_ = os.Remove(confPath)
		stopProbeClient()
		fmt.Println("probe removed")
		return nil
	}

	priv, pub, err := probeKey(keyPath)
	if err != nil {
		return err
	}
	if *printKey {
		fmt.Printf("probe public key: %s\n", pub)
		fmt.Println("add it on Aegis, then run again with --ip <address>:")
		fmt.Printf("  wg set wg0 peer %s allowed-ips <address>/32\n", pub)
		return nil
	}
	if *ip == "" {
		return errors.New("--ip is required (the address the server assigned to this probe peer)")
	}

	if err := plat.InstallTools(); err != nil {
		return fmt.Errorf("WireGuard: %w", err)
	}
	if _, err := plat.InstallWstunnel(); err != nil {
		return fmt.Errorf("tunneler: %w", err)
	}

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32

[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = %s
PersistentKeepalive = 25
`, priv, *ip, core.AegisPublicKey, *allowed, net.JoinHostPort(core.RelayHost, core.RelayPort))
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return err
	}

	if err := startProbeClient(); err != nil {
		return err
	}
	// Wait for the local UDP forward the tunnel points at. A tunnel whose
	// endpoint nobody listens on sends handshakes into the void and looks
	// exactly like a blocked network, so fail with the real reason.
	deadline := time.Now().Add(20 * time.Second)
	held := false
	for time.Now().Before(deadline) {
		if udpListening(core.RelayHost, core.RelayPort) {
			held = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !held {
		return fmt.Errorf("the probe tunneler is not listening on %s; see the log for its output",
			net.JoinHostPort(core.RelayHost, core.RelayPort))
	}

	exe := wireguardExeFor()
	if exe == "" {
		return errors.New("wireguard.exe not found after install")
	}
	// A previous run leaves the service installed, and WireGuard refuses to
	// install over one that still exists. Uninstall, wait for it to disappear,
	// then install.
	_ = exec.Command(exe, "/uninstalltunnelservice", service).Run()
	for i := 0; i < 20 && tunnelServiceExists(service); i++ {
		time.Sleep(500 * time.Millisecond)
	}
	if out, err := exec.Command(exe, "/installtunnelservice", confPath).CombinedOutput(); err != nil {
		return fmt.Errorf("install probe tunnel: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	// WireGuard removes the service again when it cannot start, which looks
	// like a missing service a second later. Wait for RUNNING and say so.
	running := false
	for i := 0; i < 30; i++ {
		if tunnelServiceRunning(service) {
			running = true
			break
		}
		if !tunnelServiceExists(service) {
			return fmt.Errorf("the tunnel service %s was removed immediately after install; WireGuard could not start it", service)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !running {
		return fmt.Errorf("the tunnel service %s did not reach RUNNING", service)
	}

	fmt.Println("probing", *allowed, "through the WebSocket tunnel")
	// Judge success by the WireGuard handshake, not by a ping. On a machine
	// whose host already tunnels to Aegis, a ping to 10.88.0.1 succeeds anyway
	// and would report a dead probe tunnel as working.
	var last error
	for attempt := 0; attempt < 8; attempt++ {
		time.Sleep(2 * time.Second)
		if probeHandshaked(service) {
			fmt.Println("[ok] handshake completed over wg0ws-probe")
			fmt.Printf("probe public key: %s\n", pub)
			fmt.Println("remove it with `egress wg-probe --cleanup`")
			return nil
		}
		last = fmt.Errorf("no handshake on %s yet", service)
	}
	return fmt.Errorf("probe failed: %v (SOCKS relay untouched; run --cleanup to remove)", last)
}

// probeKey loads or creates the probe keypair, so re-runs keep one peer.
func probeKey(path string) (privB64, pubB64 string, err error) {
	curve := ecdh.X25519()
	var priv *ecdh.PrivateKey
	if data, rerr := os.ReadFile(path); rerr == nil {
		raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr == nil && len(raw) == 32 {
			priv, err = curve.NewPrivateKey(raw)
		}
	}
	if priv == nil {
		priv, err = curve.GenerateKey(rand.Reader)
		if err != nil {
			return "", "", err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return "", "", err
		}
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Bytes())+"\n"), 0600); err != nil {
			return "", "", err
		}
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// startProbeClient runs a second wstunnel client whose only job is the UDP
// forward the probe tunnel dials. It is separate from the one the split proxy
// already runs, which carries TCP.
func startProbeClient() error {
	path, err := wstunnel.Find()
	if err != nil {
		return err
	}
	cmd := exec.Command(path, "client",
		"--http-upgrade-path-prefix", core.WstunnelPrefix,
		"--dns-resolver", "dns://"+core.DoHListenAddr,
		"--dns-resolver-prefer-ipv4",
		"--tls-verify-certificate",
		"-L", "udp://"+net.JoinHostPort(core.RelayHost, core.RelayPort)+":"+net.JoinHostPort(core.RelayHost, core.AegisWGPort),
		"wss://"+core.DoHHost,
	)
	cmd.Stdout = logx.Logger().Writer()
	cmd.Stderr = logx.Logger().Writer()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start probe tunneler: %w", err)
	}
	_ = os.WriteFile(filepath.Join(core.InstallDir(), "wg-probe.pid"),
		[]byte(fmt.Sprintf("%d\n", cmd.Process.Pid)), 0600)
	return nil
}

func stopProbeClient() {
	if data, err := os.ReadFile(filepath.Join(core.InstallDir(), "wg-probe.pid")); err == nil {
		var pid int
		if _, perr := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); perr == nil && pid > 4 {
			_ = exec.Command("taskkill", "/PID", fmt.Sprint(pid), "/F").Run()
		}
	}
	_ = os.Remove(filepath.Join(core.InstallDir(), "wg-probe.pid"))
}

func udpListening(host, port string) bool {
	conn, err := net.ListenPacket("udp", net.JoinHostPort(host, port))
	if err != nil {
		return true // something already holds it
	}
	_ = conn.Close()
	return false
}

func wireguardExeFor() string {
	for _, p := range []string{
		`C:\Program Files\WireGuard\wireguard.exe`,
		`C:\Program Files (x86)\WireGuard\wireguard.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// tunnelServiceExists reports whether the WireGuard tunnel service is present.
func tunnelServiceExists(name string) bool {
	out, err := exec.Command("sc.exe", "query", "WireGuardTunnel$"+name).CombinedOutput()
	if err != nil {
		return false
	}
	text := string(out)
	return strings.Contains(text, "RUNNING") || strings.Contains(text, "STOPPED")
}

// probeHandshaked asks WireGuard itself whether the peer completed a handshake.
// wg.exe ships with WireGuard for Windows; when it is missing the probe says so
// rather than falling back to a ping that can be fooled by the host's tunnel.
func probeHandshaked(iface string) bool {
	wg := filepath.Join(filepath.Dir(wireguardExeFor()), "wg.exe")
	out, err := exec.Command(wg, "show", iface).CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "latest handshake") && !strings.Contains(line, "never") {
			return true
		}
	}
	return false
}

// tunnelServiceRunning reports whether the tunnel service is in RUNNING state.
func tunnelServiceRunning(name string) bool {
	out, err := exec.Command("sc.exe", "query", "WireGuardTunnel$"+name).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "RUNNING")
}
