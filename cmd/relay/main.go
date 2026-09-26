package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"tyd/internal/relay"
)

func main() {
	listenDefault := envOr("TYD_RELAY_LISTEN", "127.0.0.1:9090")
	addr := flag.String("listen", listenDefault, "TCP listen address (env TYD_RELAY_LISTEN)")
	flag.Parse()

	lnAddr, closeFn, err := relay.ListenAndServe(*addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "tyd relay listening on %s\n", lnAddr.String())
	fmt.Fprintln(os.Stderr, "blind splice only; put TLS at the edge (e.g. Cloudflare) for production")
	fmt.Fprintln(os.Stderr, "servers: tyd up --relay https://relay.getfda.dev")
	fmt.Fprintln(os.Stderr, "clients fall back to the same --relay after direct dial fails")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	_ = closeFn()
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
