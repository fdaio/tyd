package relay

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// An idle splice used to die at ~125s: io.Copy writes nothing, and Cloudflare
// closes the quiet WebSocket. Ping frames must keep the legs alive without
// ever showing up in the bytes the two peers exchange.
func TestSplicePingDoesNotEnterByteStream(t *testing.T) {
	prev := splicePingInterval
	splicePingInterval = 30 * time.Millisecond
	t.Cleanup(func() { splicePingInterval = prev })

	lnAddr, closeFn, err := ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeFn() })
	wsURL, err := WebSocketURL("http://" + lnAddr.String())
	if err != nil {
		t.Fatal(err)
	}

	var dialPings, acceptPings atomic.Int32
	offerNC := dialWS(t, wsURL, nil)
	dialNC := dialWS(t, wsURL, func(context.Context, []byte) bool {
		dialPings.Add(1)
		return true
	})

	if err := WriteMsg(offerNC, Msg{Type: TypeOffer, DaemonID: "daemon-ping"}); err != nil {
		t.Fatal(err)
	}
	ack, err := readMsgWithin(offerNC, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Type != TypeOK {
		t.Fatalf("offer ack: %+v", ack)
	}

	dialReady := make(chan error, 1)
	go func() {
		if err := WriteMsg(dialNC, Msg{Type: TypeDial, PeerID: "daemon-ping"}); err != nil {
			dialReady <- err
			return
		}
		msg, err := readMsgWithin(dialNC, 5*time.Second)
		if err != nil {
			dialReady <- err
			return
		}
		if msg.Type != TypeOK {
			dialReady <- errUnexpected(msg.Type)
			return
		}
		dialReady <- nil
	}()

	incoming, err := readMsgWithin(offerNC, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if incoming.Type != TypeIncoming || incoming.Ticket == "" {
		t.Fatalf("incoming: %+v", incoming)
	}

	acceptNC := dialWS(t, wsURL, func(context.Context, []byte) bool {
		acceptPings.Add(1)
		return true
	})
	if err := WriteMsg(acceptNC, Msg{Type: TypeAccept, Ticket: incoming.Ticket}); err != nil {
		t.Fatal(err)
	}
	acceptAck, err := readMsgWithin(acceptNC, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if acceptAck.Type != TypeOK {
		t.Fatalf("accept ack: %+v", acceptAck)
	}
	if err := <-dialReady; err != nil {
		t.Fatal(err)
	}

	// Readers have to be in Read for the peer stack to answer ping with pong.
	dialBuf := &byteBuf{}
	acceptBuf := &byteBuf{}
	go readUntilClose(dialNC, dialBuf)
	go readUntilClose(acceptNC, acceptBuf)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (dialPings.Load() < 2 || acceptPings.Load() < 2) {
		time.Sleep(10 * time.Millisecond)
	}
	if dialPings.Load() < 2 || acceptPings.Load() < 2 {
		t.Fatalf("pings before data: dial=%d accept=%d", dialPings.Load(), acceptPings.Load())
	}

	fromDial := []byte("from-dial")
	if _, err := dialNC.Write(fromDial); err != nil {
		t.Fatal(err)
	}
	waitEqual(t, acceptBuf, fromDial)

	fromAccept := []byte("from-accept")
	if _, err := acceptNC.Write(fromAccept); err != nil {
		t.Fatal(err)
	}
	waitEqual(t, dialBuf, fromAccept)

	if got := acceptBuf.snapshot(); string(got) != string(fromDial) {
		t.Fatalf("accept leg changed after reverse write: %q", got)
	}
}

func dialWS(t *testing.T, wsURL string, onPing func(context.Context, []byte) bool) net.Conn {
	t.Helper()
	ws, _, err := websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{
		OnPingReceived: onPing,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close(websocket.StatusNormalClosure, "") })
	return websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
}

func readMsgWithin(c net.Conn, d time.Duration) (Msg, error) {
	_ = c.SetReadDeadline(time.Now().Add(d))
	msg, err := ReadMsg(c)
	_ = c.SetReadDeadline(time.Time{})
	return msg, err
}

type unexpectedType string

func (e unexpectedType) Error() string { return "unexpected message type " + string(e) }

func errUnexpected(typ string) error { return unexpectedType(typ) }

type byteBuf struct {
	mu sync.Mutex
	b  []byte
}

func (b *byteBuf) append(p []byte) {
	b.mu.Lock()
	b.b = append(b.b, p...)
	b.mu.Unlock()
}

func (b *byteBuf) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.b...)
}

func readUntilClose(c net.Conn, buf *byteBuf) {
	tmp := make([]byte, 64)
	for {
		n, err := c.Read(tmp)
		if n > 0 {
			buf.append(tmp[:n])
		}
		if err != nil {
			return
		}
	}
}

func waitEqual(t *testing.T, buf *byteBuf, want []byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got := buf.snapshot()
		if string(got) == string(want) {
			return
		}
		if len(got) > len(want) {
			t.Fatalf("byte stream %q, want %q", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("byte stream %q, want %q", buf.snapshot(), want)
}
