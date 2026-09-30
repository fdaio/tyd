package transport

import (
	"crypto/tls"
	"fmt"
	"net"
)

type Kind string

const (
	KindUnix Kind = "unix"
	KindTLS  Kind = "tls"
	KindQUIC Kind = "quic"
	KindRelay Kind = "relay"
)

// Endpoint identifies how to listen or dial.
type Endpoint struct {
	Kind    Kind
	Address string // unix path or host:port
}

func (e Endpoint) String() string {
	if e.Kind == "" {
		return e.Address
	}
	return string(e.Kind) + "://" + e.Address
}

// Conn is a transport connection with topology metadata.
type Conn interface {
	net.Conn
	Info() Info
}

type Info struct {
	Transport  Kind   `json:"transport"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	TLS        bool   `json:"tls"`
	CertFP     string `json:"cert_fp,omitempty"` // short SHA-256 fingerprint of peer/server cert
}

type wrapped struct {
	net.Conn
	info Info
}

func (w *wrapped) Info() Info { return w.info }

func Wrap(c net.Conn, info Info) Conn {
	if info.LocalAddr == "" && c.LocalAddr() != nil {
		info.LocalAddr = c.LocalAddr().String()
	}
	if info.RemoteAddr == "" && c.RemoteAddr() != nil {
		info.RemoteAddr = c.RemoteAddr().String()
	}
	return &wrapped{Conn: c, info: info}
}

// ChannelBinder returns the value that ties a signature to this connection: the
// TLS exporter, which no other session derives. Every transport that carries
// TLS goes through here, so the auth response is bound to the session it was
// made on. A unix socket has no TLS session and reports no binding.
//
// A connection of an unknown type is an error rather than no binding. Falling
// back would authenticate such a connection over the bare nonce, which is what
// a peer needs to carry a login between daemons.
//
// On the server side of a TLS listener the handshake has not run yet when
// Accept returns, so this reports an error until the connection has written
// something. That is fine for the auth flow, which challenges first.
func ChannelBinder(conn net.Conn) ([]byte, error) {
	switch c := conn.(type) {
	case *wrapped:
		return ChannelBinder(c.Conn)
	case *tls.Conn:
		state := c.ConnectionState()
		return Binder(&state)
	case *quicStreamConn:
		state := c.sess.ConnectionState()
		return Binder(&state.TLS)
	case *net.UnixConn:
		return nil, nil
	}
	return nil, fmt.Errorf("no channel binding for a %T connection", conn)
}
