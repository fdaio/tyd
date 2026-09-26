package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"tyd/internal/controlpanel"
)

func main() {
	listenDefault := envOr("TYD_CP_LISTEN", "127.0.0.1:8080")
	baseDefault := envOr("TYD_CP_BASE_URL", "")
	releaseDefault := envOr("TYD_CP_RELEASE_DIR", "")

	addr := flag.String("listen", listenDefault, "HTTP listen address (env TYD_CP_LISTEN)")
	baseURL := flag.String("base-url", baseDefault, "public base URL for register responses (env TYD_CP_BASE_URL)")
	releaseDir := flag.String("release-dir", releaseDefault, "directory of tyd-*.tar.gz served at /releases/ (env TYD_CP_RELEASE_DIR)")
	flag.Parse()

	svc := controlpanel.New()
	if u := strings.TrimRight(strings.TrimSpace(*baseURL), "/"); u != "" {
		svc.SetBaseURL(u)
	}
	if d := strings.TrimSpace(*releaseDir); d != "" {
		svc.SetReleaseDir(d)
	}
	lnAddr, srv, err := controlpanel.ListenAndServe(*addr, svc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "tyd control panel listening on http://%s\n", lnAddr.String())
	if u := strings.TrimSpace(*baseURL); u != "" {
		u = strings.TrimRight(u, "/")
		fmt.Fprintf(os.Stderr, "public base URL %s\n", u)
		fmt.Fprintf(os.Stderr, "install script %s/install.sh\n", u)
		if strings.TrimSpace(*releaseDir) != "" {
			fmt.Fprintf(os.Stderr, "release archives %s/releases/\n", u)
		}
	} else {
		fmt.Fprintf(os.Stderr, "install script http://%s/install.sh\n", lnAddr.String())
		if strings.TrimSpace(*releaseDir) != "" {
			fmt.Fprintf(os.Stderr, "release archives http://%s/releases/\n", lnAddr.String())
		}
	}
	fmt.Fprintln(os.Stderr, "pairing metadata only; no session/TTY storage; state is in-memory")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	_ = srv.Close()
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
