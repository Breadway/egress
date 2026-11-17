// Command egress-exit learns which destination prefixes the cloud exit is
// refused on and routes them through the residential exit instead.
//
// It runs on the exit host (Aegis), not on client devices. Candidates come from
// the fleet's shared block table, so a site that starts refusing the cloud exit
// is learned without anyone hardcoding it.
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
	statePath := flag.String("state", "/var/lib/egress-exit/state.json", "where learned prefixes are saved")
	interval := flag.Duration("interval", 10*time.Minute, "how often to re-check")
	ttl := flag.Duration("ttl", 7*24*time.Hour, "how long a learned prefix is trusted")
	exitDev := flag.String("exit-dev", "wg0", "interface that reaches the residential exit")
	cloudDev := flag.String("cloud-dev", "ens3", "interface of the cloud exit")
	limit := flag.Int("limit", 400, "maximum prefixes to route")
	once := flag.Bool("once", false, "run one cycle and exit")
	dryRun := flag.Bool("dry-run", false, "report decisions without changing routes")
	verbose := flag.Bool("verbose", false, "log every probe decision")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	logf := func(format string, args ...any) {}
	if *verbose || !*once {
		logf = logger.Printf
	}

	learner, err := exitroute.New(exitroute.Options{
		FeedDir:      *feedDir,
		ExtraDomains: *extra,
		StatePath:    *statePath,
		Interval:     *interval,
		TTL:          *ttl,
		ExitDev:      *exitDev,
		CloudDev:     *cloudDev,
		Limit:        *limit,
		DryRun:       *dryRun,
		Logf:         logf,
	})
	if err != nil {
		logger.Fatalf("exit: %v", err)
	}

	if *once {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		sum, err := learner.RunOnce(ctx)
		if err != nil {
			logger.Fatalf("exit: %v", err)
		}
		fmt.Printf("checked %d of %d blocked names; added %v; removed %v\n",
			sum.Checked, sum.Candidates, sum.Added, sum.Removed)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := learner.Run(ctx); err != nil {
		logger.Fatalf("exit: %v", err)
	}
}
