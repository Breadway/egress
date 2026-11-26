package health

import (
	"context"
	"egress/internal/core"
	"egress/internal/logx"
	"egress/internal/platform"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func CheckLocalDNS() error {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", core.DoHListenAddr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := resolver.LookupIP(ctx, "ip4", "example.com")
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return errors.New("no addresses returned")
	}
	return nil
}

// exitCheckAttempts bounds how many times the exit lookup retries, and
// exitCheckBackoff spaces the attempts. One blip of a third-party checker
// must not destroy an otherwise working install.
const (
	exitCheckAttempts = 3
	exitCheckBackoff  = 2 * time.Second
)

// ExitUnverifiedPrefix marks an Exit value where the checker was
// unreachable: the address is unknown, not wrong. verifyAll warns instead
// of failing, and grade stays partial instead of rolling back.
const ExitUnverifiedPrefix = "unverified: "

func checkExitIPOnce(timeout time.Duration) (string, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 8 * time.Second}
			return d.DialContext(ctx, "tcp4", addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	req, err := http.NewRequest(http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("exit check returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// checkExitIP asks the checker for the exit address, retrying transient
// failures. A wrong answer is returned as-is (fatal); an unreachable
// checker is an error the caller downgrades to unverified.
func checkExitIP() (string, error) {
	var err error
	var ip string
	for attempt := 0; attempt < exitCheckAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(exitCheckBackoff)
		}
		if ip, err = checkExitIPOnce(10 * time.Second); err == nil {
			return ip, nil
		}
		logx.Debugf("exit check attempt %d failed: %v", attempt+1, err)
	}
	return "", err
}

// Results holds one install verification as data, so the CLI output and
// the phone-home report describe the same run.
type Results struct {
	DNS    string `json:"dns,omitempty"`    // error text, empty when ok
	Tunnel string `json:"tunnel,omitempty"` // "up", "down", or "skipped"
	Probe  string `json:"probe,omitempty"`  // "ok", "failed", or "skipped"
	Exit   string `json:"exit,omitempty"`   // exit IP, error text, or skipped ("")
	// Supervisor holds the error when the boot service is not our live
	// supervisor, even if something else answers on the DNS port.
	Supervisor string `json:"supervisor,omitempty"`
	// Split reports the Windows split client: "ok", an error, or empty when
	// the platform has no split client to check.
	Split string `json:"split,omitempty"`
}

// describeSplit adds the Windows split client's state to a result set. It is
// deliberately not part of runChecks: install verifies before split setup has
// run, so a split probe there would fail every fresh install.
// DescribeSplit judges the split path by its tunnel. The per-user proxy and
// PAC are being retired: blocked destinations are routed into WireGuard, so a
// running relay tunnel is what "split works" now means.
func DescribeSplit(r Results, tcfg core.TunnelConfig) Results {
	if !tcfg.Split {
		return r
	}
	switch r.Tunnel {
	case "up":
		r.Split = "ok"
	case "skipped":
		r.Split = ""
	default:
		r.Split = "the relay tunnel is down"
	}
	return r
}

func RunChecks(p platform.Interface, tcfg core.TunnelConfig) Results {
	var r Results
	if err := CheckLocalDNS(); err != nil {
		r.DNS = err.Error()
	}
	if err := CheckSupervisorLive(p, 0); err != nil {
		r.Supervisor = err.Error()
	}
	if tcfg.PrivateKey == "" {
		r.Tunnel = "skipped"
		r.Probe = "skipped"
		return r
	}
	if p.TunnelUp() {
		r.Tunnel = "up"
	} else {
		r.Tunnel = "down"
	}
	if p.Ping(core.AegisTunnelIP) {
		r.Probe = "ok"
	} else {
		r.Probe = "failed"
	}
	// Split is the only mode: ordinary traffic stays on the physical link, so
	// the public exit address is not Aegis and is not checked.
	r.Exit = "split"
	return r
}

// grade maps check results to the status the admin UI shows.
func (r Results) Grade() string {
	// DNS answering while our supervisor is down means a foreign process
	// holds the port: never report that as healthy.
	if r.DNS != "" || r.Supervisor != "" {
		return "failed"
	}
	if r.Split != "" && r.Split != "ok" {
		return "failed"
	}
	if (r.Tunnel == "up" || r.Tunnel == "skipped") &&
		(r.Probe == "ok" || r.Probe == "skipped") &&
		(r.Exit == "" || r.Exit == core.AegisIPv4 || r.Exit == "split") {
		return "functional"
	}
	return "partial"
}

func (r Results) failed() bool {
	if r.DNS != "" {
		return true
	}
	return r.Grade() != "functional"
}

func VerifyAll(p platform.Interface, tcfg core.TunnelConfig, checkSplit bool) error {
	r := RunChecks(p, tcfg)
	if checkSplit {
		r = DescribeSplit(r, tcfg)
	}
	failed := false

	if r.DNS != "" {
		fmt.Printf("[FAIL] dns through %s: %v\n", core.DoHListenAddr, r.DNS)
		failed = true
	} else {
		fmt.Printf("[ok]   dns through %s\n", core.DoHListenAddr)
	}

	if r.Supervisor != "" {
		fmt.Printf("[FAIL] supervisor: %v\n", r.Supervisor)
		failed = true
	} else {
		fmt.Println("[ok]   supervisor is ours and running")
	}

	if checkSplit && r.Split != "" {
		if r.Split == "ok" {
			fmt.Println("[ok]   split routing: relay tunnel is up")
		} else {
			fmt.Printf("[FAIL] split client: %s\n", r.Split)
			failed = true
		}
	}

	if tcfg.PrivateKey != "" && !tcfg.NoTunnel {
		if r.Tunnel == "up" {
			fmt.Println("[ok]   wireguard tunnel is up")
		} else {
			fmt.Println("[FAIL] wireguard tunnel is down")
			failed = true
		}

		if r.Probe == "ok" {
			fmt.Printf("[ok]   %s answers through the tunnel\n", core.AegisTunnelIP)
		} else if tcfg.Split {
			// A split client only routes learned destinations into the tunnel,
			// and some networks drop ICMP at the exit. A fresh handshake and
			// moving counters prove the tunnel carries traffic; failing here
			// said "broken" on a device that was working.
			fmt.Printf("[warn] %s did not answer a ping; the tunnel handshake is the authority for split mode\n",
				core.AegisTunnelIP)
		} else {
			fmt.Printf("[FAIL] %s does not answer through the tunnel\n", core.AegisTunnelIP)
			failed = true
		}

		switch {
		case tcfg.Split && r.Exit == "split":
			fmt.Println("[ok]   split routing: only learned-blocked destinations use the tunnel")
		case r.Exit == core.AegisIPv4:
			fmt.Printf("[ok]   exit address is %s\n", r.Exit)
		case r.Exit == "":
			fmt.Printf("[FAIL] exit address: no result\n")
			failed = true
		case strings.HasPrefix(r.Exit, ExitUnverifiedPrefix):
			fmt.Printf("[warn] exit address %s; tunnel and probe passed so keeping the install\n",
				strings.TrimPrefix(r.Exit, ExitUnverifiedPrefix))
		default:
			fmt.Printf("[FAIL] exit address: %s\n", r.Exit)
			failed = true
		}
	}

	if failed {
		return errors.New("verification failed")
	}
	return nil
}

// CheckSystemDNS resolves through /etc/resolv.conf, which is what every other
// program on the machine uses. The egress listener can be healthy while this
// path is not: Tailscale's MagicDNS once took the file over and stopped
// answering, and a scan failed with a resolv.conf it should not have trusted.
// The CLI reports this; egress's own lookups no longer depend on it.
func CheckSystemDNS() error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupHost(ctx, "example.com"); err != nil {
		if servers := resolvServers(); servers != "" {
			hint := ""
			if tailscaleDNSEnabled() {
				hint = "; Tailscale MagicDNS is enabled, run `tailscale set --accept-dns=false` so egress can own DNS"
			}
			return fmt.Errorf("%v (resolv.conf: %s%s)", err, servers, hint)
		}
		return err
	}
	return nil
}

func tailscaleDNSEnabled() bool {
	out, err := exec.Command("tailscale", "dns", "status").Output()
	return err == nil && strings.Contains(string(out), "Tailscale DNS: enabled")
}

// resolvServers returns the nameserver lines for the error message. Empty when
// the platform has no resolv.conf.
func resolvServers() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	return strings.Join(servers, ", ")
}
