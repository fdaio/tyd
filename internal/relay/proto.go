// Package relay is a blind byte-pipe rendezvous for dual-NAT peers.
// Control messages use length-prefixed JSON; after a successful dial/accept
// handshake the connection becomes a raw bidirectional pipe for tyd frames.
package relay

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const MaxMsg = 64 << 10

// Message types on the control channel before splicing.
const (
	TypeOffer    = "offer"    // server: I am daemon_id, keep this control conn
	TypeDial     = "dial"     // client: connect me to peer_id
	TypeAccept   = "accept"   // server: claim ticket on a new data conn
	TypeIncoming = "incoming" // relay → server control: client waiting with ticket
	TypeOK       = "ok"       // relay → dial/accept: splice begins after this frame
	TypeError    = "error"
)

type Msg struct {
	Type     string `json:"type"`
	DaemonID string `json:"daemon_id,omitempty"`
	PeerID   string `json:"peer_id,omitempty"`
	Ticket   string `json:"ticket,omitempty"`
	Error    string `json:"error,omitempty"`
}

func WriteMsg(w io.Writer, m Msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > MaxMsg {
		return fmt.Errorf("relay message too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func ReadMsg(r io.Reader) (Msg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Msg{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	// 0x48545450 == "HTTP" — edge returned an HTTP page instead of WebSocket.
	if n == 0x48545450 {
		return Msg{}, fmt.Errorf("relay: got HTTP response (need WebSocket; is the relay up behind TLS?)")
	}
	if n == 0 || n > MaxMsg {
		return Msg{}, fmt.Errorf("relay message length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Msg{}, err
	}
	var m Msg
	if err := json.Unmarshal(buf, &m); err != nil {
		return Msg{}, err
	}
	return m, nil
}

// WebSocketURL turns a relay URL into a ws/wss URL for dialing.
// https://host[/path] → wss://host[/path]; http://host:port → ws://host:port/
func WebSocketURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "off" {
		return "", fmt.Errorf("relay disabled")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("relay URL missing host: %q", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported relay scheme %q", u.Scheme)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

// DialTarget is kept for tests/diagnostics: host:port and whether TLS is used.
func DialTarget(raw string) (addr string, useTLS bool, err error) {
	wsURL, err := WebSocketURL(raw)
	if err != nil {
		return "", false, err
	}
	u, err := url.Parse(wsURL)
	if err != nil {
		return "", false, err
	}
	host := u.Host
	useTLS = u.Scheme == "wss"
	if !strings.Contains(host, ":") {
		if useTLS {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host, useTLS, nil
}
