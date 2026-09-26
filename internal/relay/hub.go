package relay

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type pendingDial struct {
	client   net.Conn
	acceptCh chan net.Conn
	finished chan struct{}
}

type offer struct {
	daemonID string
	control  net.Conn
	writeMu  sync.Mutex
}

// Hub matches a long-lived server offer with client dials.
type Hub struct {
	mu      sync.Mutex
	offers  map[string]*offer
	tickets map[string]*pendingDial
}

func NewHub() *Hub {
	return &Hub{
		offers:  make(map[string]*offer),
		tickets: make(map[string]*pendingDial),
	}
}

func (h *Hub) Handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	msg, err := ReadMsg(conn)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return
	}
	switch msg.Type {
	case TypeOffer:
		h.handleOffer(conn, msg)
	case TypeDial:
		h.handleDial(conn, msg)
	case TypeAccept:
		h.handleAccept(conn, msg)
	default:
		_ = WriteMsg(conn, Msg{Type: TypeError, Error: "unknown type"})
	}
}

func (h *Hub) handleOffer(conn net.Conn, msg Msg) {
	id := strings.TrimSpace(msg.DaemonID)
	if id == "" {
		_ = WriteMsg(conn, Msg{Type: TypeError, Error: "daemon_id required"})
		return
	}
	o := &offer{daemonID: id, control: conn}
	h.mu.Lock()
	if old, ok := h.offers[id]; ok {
		_ = old.control.Close()
	}
	h.offers[id] = o
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		if cur, ok := h.offers[id]; ok && cur == o {
			delete(h.offers, id)
		}
		h.mu.Unlock()
	}()
	if err := WriteMsg(conn, Msg{Type: TypeOK}); err != nil {
		return
	}
	// Server only reads Incoming on this conn; we detect disconnect via Read EOF.
	buf := make([]byte, 1)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			return
		}
	}
}

func (h *Hub) handleDial(conn net.Conn, msg Msg) {
	peer := strings.TrimSpace(msg.PeerID)
	if peer == "" {
		_ = WriteMsg(conn, Msg{Type: TypeError, Error: "peer_id required"})
		return
	}
	h.mu.Lock()
	o, ok := h.offers[peer]
	h.mu.Unlock()
	if !ok {
		_ = WriteMsg(conn, Msg{Type: TypeError, Error: "peer offline"})
		return
	}
	ticket := newTicket()
	pd := &pendingDial{
		client:   conn,
		acceptCh: make(chan net.Conn, 1),
		finished: make(chan struct{}),
	}
	h.mu.Lock()
	h.tickets[ticket] = pd
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.tickets, ticket)
		h.mu.Unlock()
		close(pd.finished)
	}()

	o.writeMu.Lock()
	err := WriteMsg(o.control, Msg{Type: TypeIncoming, Ticket: ticket})
	o.writeMu.Unlock()
	if err != nil {
		_ = WriteMsg(conn, Msg{Type: TypeError, Error: "peer unreachable"})
		return
	}

	var accept net.Conn
	timer := time.NewTimer(25 * time.Second)
	defer timer.Stop()
	select {
	case accept = <-pd.acceptCh:
	case <-timer.C:
		_ = WriteMsg(conn, Msg{Type: TypeError, Error: "accept timeout"})
		return
	}
	defer accept.Close()

	if err := WriteMsg(conn, Msg{Type: TypeOK, Ticket: ticket}); err != nil {
		return
	}
	if err := WriteMsg(accept, Msg{Type: TypeOK, Ticket: ticket}); err != nil {
		return
	}
	splice(conn, accept)
}

func (h *Hub) handleAccept(conn net.Conn, msg Msg) {
	ticket := strings.TrimSpace(msg.Ticket)
	if ticket == "" {
		_ = WriteMsg(conn, Msg{Type: TypeError, Error: "ticket required"})
		return
	}
	h.mu.Lock()
	pd, ok := h.tickets[ticket]
	h.mu.Unlock()
	if !ok {
		_ = WriteMsg(conn, Msg{Type: TypeError, Error: "unknown ticket"})
		return
	}
	select {
	case pd.acceptCh <- conn:
		<-pd.finished
	case <-time.After(5 * time.Second):
		_ = WriteMsg(conn, Msg{Type: TypeError, Error: "dial gone"})
	}
}

func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
		_ = src.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

func newTicket() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
