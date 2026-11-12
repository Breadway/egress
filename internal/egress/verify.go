package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func checkLocalDNS() error {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", dohListenAddr)
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

// exitUnverifiedPrefix marks an Exit value where the checker was
// unreachable: the address is unknown, not wrong. verifyAll warns instead
// of failing, and grade stays partial instead of rolling back.
const exitUnverifiedPrefix = "unverified: "

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
		debugf("exit check attempt %d failed: %v", attempt+1, err)
	}
	return "", err
}

// checkResults holds one install verification as data, so the CLI output and
// the phone-home report describe the same run.
type checkResults struct {
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
func describeSplit(r checkResults, tcfg tunnelConfig) checkResults {
	if tcfg.Split {
		r.Split = checkWindowsSplit()
	}
	return r
}

func runChecks(p platform, tcfg tunnelConfig) checkResults {
	var r checkResults
	if err := checkLocalDNS(); err != nil {
		r.DNS = err.Error()
	}
	if err := checkSupervisorLive(p, 0); err != nil {
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
	if p.Ping(aegisTunnelIP) {
		r.Probe = "ok"
	} else {
		r.Probe = "failed"
	}
	if tcfg.Split {
		// Split mode deliberately leaves most traffic on the physical link,
		// so the public exit address is not Aegis and is not checked.
		r.Exit = "split"
		return r
	}
	ip, err := checkExitIP()
	switch {
	case err != nil:
		// The checker was unreachable, not wrong: the tunnel and probe
		// checks already establish traffic enters the tunnel, so record
		// uncertainty instead of destroying the install.
		r.Exit = exitUnverifiedPrefix + err.Error()
	case ip == aegisIPv4:
		r.Exit = ip
	default:
		r.Exit = "got " + ip + ", expected " + aegisIPv4
	}
	return r
}

// grade maps check results to the status the admin UI shows.
func (r checkResults) grade() string {
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
		(r.Exit == "" || r.Exit == aegisIPv4 || r.Exit == "split") {
		return "functional"
	}
	return "partial"
}

func (r checkResults) failed() bool {
	if r.DNS != "" {
		return true
	}
	return r.grade() != "functional"
}

func verifyAll(p platform, tcfg tunnelConfig, checkSplit bool) error {
	r := runChecks(p, tcfg)
	if checkSplit {
		r = describeSplit(r, tcfg)
	}
	failed := false

	if r.DNS != "" {
		fmt.Printf("[FAIL] dns through %s: %v\n", dohListenAddr, r.DNS)
		failed = true
	} else {
		fmt.Printf("[ok]   dns through %s\n", dohListenAddr)
	}

	if r.Supervisor != "" {
		fmt.Printf("[FAIL] supervisor: %v\n", r.Supervisor)
		failed = true
	} else {
		fmt.Println("[ok]   supervisor is ours and running")
	}

	if checkSplit && r.Split != "" {
		if r.Split == "ok" {
			fmt.Println("[ok]   split client: proxy and PAC in place")
		} else {
			fmt.Printf("[FAIL] split client: %s\n", r.Split)
			failed = true
		}
	}

	if tcfg.PrivateKey != "" {
		if r.Tunnel == "up" {
			fmt.Println("[ok]   wireguard tunnel is up")
		} else {
			fmt.Println("[FAIL] wireguard tunnel is down")
			failed = true
		}

		if r.Probe == "ok" {
			fmt.Printf("[ok]   %s answers through the tunnel\n", aegisTunnelIP)
		} else {
			fmt.Printf("[FAIL] %s does not answer through the tunnel\n", aegisTunnelIP)
			failed = true
		}

		switch {
		case tcfg.Split && r.Exit == "split":
			fmt.Println("[ok]   split routing: only learned-blocked destinations use the tunnel")
		case r.Exit == aegisIPv4:
			fmt.Printf("[ok]   exit address is %s\n", r.Exit)
		case r.Exit == "":
			fmt.Printf("[FAIL] exit address: no result\n")
			failed = true
		case strings.HasPrefix(r.Exit, exitUnverifiedPrefix):
			fmt.Printf("[warn] exit address %s; tunnel and probe passed so keeping the install\n",
				strings.TrimPrefix(r.Exit, exitUnverifiedPrefix))
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
