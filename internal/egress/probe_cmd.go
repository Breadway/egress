package egress

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"egress/internal/split"
)

// cmdProbe classifies domains over the direct path without changing routes or
// the tunnel. On Linux, --interface pins the probe to the physical link while
// the full tunnel is up.
func cmdProbe(args []string) error {
	fs := newFlagSet("probe")
	iface := fs.String("interface", "", "bind probes to this interface (Linux only)")
	timeout := fs.Duration("timeout", split.ProbeTimeout, "per-probe timeout")
	debug := fs.Bool("debug", false, "trace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))
	if *iface != "" && runtime.GOOS != "linux" {
		return errors.New("--interface binds the probe to a physical link and is Linux-only; omit it on this platform")
	}

	domains := fs.Args()
	if len(domains) == 0 {
		return errors.New("usage: egress probe [--interface wlan0] [--timeout 5s] domain...")
	}
	for _, domain := range domains {
		ctx, cancel := context.WithTimeout(context.Background(), 3*(*timeout))
		res := split.ProbeDomain(ctx, domain, split.ProbeOptions{Interface: *iface, Timeout: *timeout})
		cancel()
		fmt.Println(res.String())
	}
	return nil
}
