package relay

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// ListenAndServe starts an HTTP server that accepts WebSocket upgrades and
// runs the rendezvous hub. Suitable behind Cloudflare (TLS at the edge).
func ListenAndServe(addr string) (net.Addr, func() error, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	hub := NewHub()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("/", hub.Handler())
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr(), srv.Close, nil
}

// MustListen is a convenience for tests.
func MustListen(addr string) (net.Addr, func() error) {
	a, closeFn, err := ListenAndServe(addr)
	if err != nil {
		panic(fmt.Sprintf("relay listen: %v", err))
	}
	return a, closeFn
}

// Handler returns an http.Handler that upgrades to WebSocket and runs the hub.
// Mount on the Control Panel at /relay so dual-NAT peers can use the same
// HTTPS origin when a dedicated relay hostname is unavailable.
func (h *Hub) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.Header.Get("Upgrade") == "" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("tyd-relay websocket\n"))
			return
		}
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Rendezvous is unauthenticated at this layer; tyd AuthN follows.
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		conn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
		h.Handle(conn)
	})
}
