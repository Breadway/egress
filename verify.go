package main

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

func checkExitIP() (string, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 8 * time.Second}
			return d.DialContext(ctx, "tcp4", addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}

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

// checkResults holds one install verification as data, so the CLI output and
// the phone-home report describe the same run.
type checkResults struct {
	DNS    string `json:"dns,omitempty"`    // error text, empty when ok
	Tunnel string `json:"tunnel,omitempty"` // "up", "down", or "skipped"
	Probe  string `json:"probe,omitempty"`  // "ok", "failed", or "skipped"
	Exit   string `json:"exit,omitempty"`   // exit IP, error text, or skipped ("")
}

func runChecks(p platform, tcfg tunnelConfig) checkResults {
	var r checkResults
	if err := checkLocalDNS(); err != nil {
		r.DNS = err.Error()
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
	ip, err := checkExitIP()
	switch {
	case err != nil:
		r.Exit = err.Error()
	case ip == aegisIPv4:
		r.Exit = ip
	default:
		r.Exit = "got " + ip + ", expected " + aegisIPv4
	}
	return r
}

// grade maps check results to the status the admin UI shows.
func (r checkResults) grade() string {
	if r.DNS != "" {
		return "failed"
	}
	if (r.Tunnel == "up" || r.Tunnel == "skipped") &&
		(r.Probe == "ok" || r.Probe == "skipped") &&
		(r.Exit == "" || r.Exit == aegisIPv4) {
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

func verifyAll(p platform, tcfg tunnelConfig) error {
	r := runChecks(p, tcfg)
	failed := false

	if r.DNS != "" {
		fmt.Printf("[FAIL] dns through %s: %v\n", dohListenAddr, r.DNS)
		failed = true
	} else {
		fmt.Printf("[ok]   dns through %s\n", dohListenAddr)
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
		case r.Exit == aegisIPv4:
			fmt.Printf("[ok]   exit address is %s\n", r.Exit)
		case r.Exit == "":
			fmt.Printf("[FAIL] exit address: no result\n")
			failed = true
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
