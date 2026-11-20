// Command wgtunnel-server terminates the WebSocket upgrade that carries
// WireGuard datagrams and forwards them to the local WireGuard listener.
//
// It runs behind Caddy on the relay: Caddy owns TLS for the public host name
// and proxies /wg-tunnel* here over loopback.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"egress/internal/wgtunnel"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:7111", "http listen address")
	target := flag.String("target", wgtunnel.DefaultServerAddr, "udp address to forward datagrams to")
	prefix := flag.String("prefix", "/wgt", "path prefix that carries the upgrade")
	flag.Parse()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           wgtunnel.Handler(*target, *prefix),
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		srv.Close()
	}()

	log.Printf("wgtunnel-server: listening on %s, forwarding to udp %s", *listen, *target)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
