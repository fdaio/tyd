package transport

import "net"

type Kind string

const (
	KindUnix Kind = "unix"
	KindTLS  Kind = "tls"
	KindQUIC Kind = "quic"
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
