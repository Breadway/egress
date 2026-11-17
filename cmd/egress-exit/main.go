// Command egress-exit routes blocked destinations through the first exit that
// serves them, including the cloud exit.
//
// It runs on the exit host (Aegis), not on client devices. Candidates come from
// the fleet's shared block table and exits come from an operator registry, so
// nothing about a site or an exit is hardcoded.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"egress/internal/exitroute"
)

func main() {
	feedDir := flag.String("feed-dir", "/var/lib/bypass/split", "directory of persisted split feeds")
	extra := flag.String("extra-domains", "/etc/egress-exit/domains", "extra candidates, one per line")
	registry := flag.String("registry", "/var/lib/bypass/exits.json", "exit registry")
	statePath := flag.String("state", "/var/lib/egress-exit/state.json", "learned assignments")
	statusPath := flag.String("status", "/var/lib/egress-exit/status.json", "published status for the admin and the fleet")
	interval := flag.Duration("interval", 10*time.Minute, "how often to re-check")
	ttl := flag.Duration("ttl", 24*time.Hour, "how long an unobserved site keeps its assignment")
	health := flag.Duration("health", 5*time.Minute, "maximum handshake age for a usable exit")
	retry := flag.Duration("retry-unserved", 30*time.Minute, "how often to retry a name no exit could serve")
	dev := flag.String("dev", "wg0", "WireGuard interface shared by the exits")
	cloudDev := flag.String("cloud-dev", "ens3", "interface of the cloud exit")
	limit := flag.Int("limit", 800, "maximum prefixes assigned in total")
	once := flag.Bool("once", false, "run one cycle and exit")
	dryRun := flag.Bool("dry-run", false, "report decisions without changing peers or routes")
	verbose := flag.Bool("verbose", false, "log every decision and assignment")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	logf := func(format string, args ...any) {}
	if *verbose || !*once {
		logf = logger.Printf
	}

	learner, err := exitroute.New(exitroute.Options{
		FeedDir:       *feedDir,
		ExtraDomains:  *extra,
		RegistryPath:  *registry,
		StatePath:     *statePath,
		StatusPath:    *statusPath,
		Interval:      *interval,
		TTL:           *ttl,
		HealthWindow:  *health,
		RetryUnserved: *retry,
		Dev:           *dev,
		CloudDev:      *cloudDev,
		Limit:         *limit,
		DryRun:        *dryRun,
		Logf:          logf,
	})
	if err != nil {
		logger.Fatalf("exit: %v", err)
	}

	if *once {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		sum, err := learner.RunOnce(ctx)
		if err != nil {
			logger.Fatalf("exit: %v", err)
		}
		fmt.Printf("checked %d of %d blocked names: %d served by an exit, %d unserved, %d changes\n",
			sum.Checked, sum.Candidates, sum.Served, sum.Unserved, sum.Changed)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := learner.Run(ctx); err != nil {
		logger.Fatalf("exit: %v", err)
	}
}
