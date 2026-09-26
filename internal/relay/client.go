package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func dialRelay(ctx context.Context, relayURL string) (net.Conn, error) {
	addr, useTLS, err := DialTarget(relayURL)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if useTLS {
		host, _, _ := net.SplitHostPort(addr)
		tlsDialer := &tls.Dialer{
			NetDialer: &d,
			Config:    &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("relay dial %s: %w", addr, err)
	}
	return conn, nil
}

// Offer keeps a control connection registered for daemonID and calls onTicket
// for each incoming client. Blocks until ctx is cancelled or the control conn dies.
func Offer(ctx context.Context, relayURL, daemonID string, onTicket func(ticket string)) error {
	if onTicket == nil {
		return fmt.Errorf("onTicket required")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := offerOnce(ctx, relayURL, daemonID, onTicket)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func offerOnce(ctx context.Context, relayURL, daemonID string, onTicket func(string)) error {
	conn, err := dialRelay(ctx, relayURL)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := WriteMsg(conn, Msg{Type: TypeOffer, DaemonID: daemonID}); err != nil {
		return err
	}
	ack, err := ReadMsg(conn)
	if err != nil {
		return err
	}
	if ack.Type == TypeError {
		return fmt.Errorf("relay offer: %s", ack.Error)
	}
	if ack.Type != TypeOK {
		return fmt.Errorf("relay offer: unexpected %q", ack.Type)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		msg, err := ReadMsg(conn)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			return err
		}
		if msg.Type == TypeIncoming && msg.Ticket != "" {
			onTicket(msg.Ticket)
			continue
		}
		if msg.Type == TypeError {
			return fmt.Errorf("relay: %s", msg.Error)
		}
	}
}

// Accept claims a ticket on a new connection and returns the spliced net.Conn
// ready for tyd frames (after the OK control message has been consumed).
func Accept(ctx context.Context, relayURL, ticket string) (net.Conn, error) {
	conn, err := dialRelay(ctx, relayURL)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if err := WriteMsg(conn, Msg{Type: TypeAccept, Ticket: ticket}); err != nil {
		return nil, err
	}
	ack, err := ReadMsg(conn)
	if err != nil {
		return nil, err
	}
	if ack.Type == TypeError {
		return nil, fmt.Errorf("relay accept: %s", ack.Error)
	}
	if ack.Type != TypeOK {
		return nil, fmt.Errorf("relay accept: unexpected %q", ack.Type)
	}
	ok = true
	return conn, nil
}

// Dial connects to peerID through the relay. The returned conn is ready for
// tyd frames (challenge/auth/session).
func Dial(ctx context.Context, relayURL, peerID string) (net.Conn, error) {
	conn, err := dialRelay(ctx, relayURL)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if err := WriteMsg(conn, Msg{Type: TypeDial, PeerID: peerID}); err != nil {
		return nil, err
	}
	ack, err := ReadMsg(conn)
	if err != nil {
		return nil, err
	}
	if ack.Type == TypeError {
		return nil, fmt.Errorf("relay dial: %s", ack.Error)
	}
	if ack.Type != TypeOK {
		return nil, fmt.Errorf("relay dial: unexpected %q", ack.Type)
	}
	ok = true
	return conn, nil
}
