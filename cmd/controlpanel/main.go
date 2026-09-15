package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"tyd/internal/controlpanel"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	flag.Parse()

	svc := controlpanel.New()
	lnAddr, srv, err := controlpanel.ListenAndServe(*addr, svc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "tyd control panel listening on http://%s\n", lnAddr.String())
	fmt.Fprintf(os.Stderr, "pairing metadata only; no session/TTY storage\n")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	_ = srv.Close()
}
