// Command wgtunnel-client runs one relay client, for diagnostics and for the
// Linux bisect of the direct-exit path.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"egress/internal/wgtunnel"
)

func main() {
	local := flag.String("local", "127.0.0.1:7109", "local UDP address for WireGuard")
	host := flag.String("host", "", "exit host name or IP")
	port := flag.String("port", "443", "exit TLS port")
	path := flag.String("path", "/wgt", "upgrade path")
	doh := flag.String("doh", "127.0.0.1:7103", "resolver for the exit host")
	flag.Parse()
	if *host == "" {
		log.Fatal("-host is required")
	}
	logger := log.New(os.Stderr, "relay: ", log.LstdFlags)
	tunnel := wgtunnel.NewWithOptions(wgtunnel.Options{
		Local: *local, Host: *host, Port: *port, Path: *path, DoH: *doh,
	}, logger)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := tunnel.Ensure(ctx); err != nil {
		log.Fatal(err)
	}
	<-ctx.Done()
}
