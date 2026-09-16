package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/protocol"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

func startTestServer(t *testing.T) (Endpoint, ed25519.PrivateKey) {
	t.Helper()
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	sock := fmt.Sprintf("/tmp/tyd-cli-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	srv := server.New(sock, session.NewManager(), trust)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ep := Endpoint{Kind: transport.KindUnix, Address: sock}
	if err := WaitReady(ep, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	return ep, key
}

func TestDialMissingSocket(t *testing.T) {
	key, _, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Dial(Endpoint{Kind: transport.KindUnix, Address: "/tmp/tyd-does-not-exist.sock"}, key)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateListClose(t *testing.T) {
	ep, key := startTestServer(t)
	info, err := Create(ep, key, CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir(), Rows: 0, Cols: 0})
	if err != nil {
		t.Fatal(err)
	}
	if info.ID == "" || info.PID == 0 {
		t.Fatalf("incomplete session: %+v", info)
	}
	listed, err := List(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range listed {
		if s.ID == info.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("created session not listed")
	}
	conns, err := Status(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) < 1 {
		t.Fatal("expected at least the status connection")
	}
	if err := CloseSession(ep, key, info.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCreateWithoutServer(t *testing.T) {
	key, _, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Create(Endpoint{Kind: transport.KindUnix, Address: "/tmp/tyd-no-server.sock"}, key, CreateOpts{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestWaitSocketTimeout(t *testing.T) {
	err := WaitSocket("/tmp/tyd-wait-missing.sock", 40*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout")
	}
}

func TestTLSCreateAndStatus(t *testing.T) {
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	sock := fmt.Sprintf("/tmp/tyd-tls-%d.sock", time.Now().UnixNano()%1_000_000)
	srv := server.NewWithConfig(server.Config{
		Socket:   sock,
		Listen:   "127.0.0.1:0",
		CertPath: cert,
		KeyPath:  keyPath,
		Mgr:      session.NewManager(),
		Trust:    trust,
	})
	// Listen 127.0.0.1:0 won't work with our ListenTLS the same way — need fixed or get addr.
	// Use a free port via temporary listener.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := tmp.Addr().String()
	_ = tmp.Close()

	srv = server.NewWithConfig(server.Config{
		Socket:   sock,
		Listen:   addr,
		CertPath: cert,
		KeyPath:  keyPath,
		Mgr:      session.NewManager(),
		Trust:    trust,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	ep := Endpoint{Kind: transport.KindTLS, Address: addr, CertPath: cert}
	if err := WaitReady(ep, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	info, err := Create(ep, key, CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	conns, err := Status(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	foundTLS := false
	for _, c := range conns {
		if c.Transport == string(transport.KindTLS) && c.TLS {
			foundTLS = true
		}
	}
	if !foundTLS {
		t.Fatalf("no tls connection in %+v", conns)
	}
	if err := CloseSession(ep, key, info.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAttachWriteAndDetach(t *testing.T) {
	ep, key := startTestServer(t)
	info, err := Create(ep, key, CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- Attach(ep, key, info.ID, inR, outW)
	}()

	if _, err := inW.Write([]byte("echo attach-client-ok\n")); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var acc []byte
	buf := make([]byte, 1024)
	for time.Now().Before(deadline) {
		_ = outR.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := outR.Read(buf)
		if n > 0 {
			acc = append(acc, buf[:n]...)
			if bytes.Contains(acc, []byte("attach-client-ok")) {
				break
			}
		}
		if err != nil && !os.IsTimeout(err) {
			t.Fatalf("read output: %v (got %q)", err, acc)
		}
	}
	if !bytes.Contains(acc, []byte("attach-client-ok")) {
		t.Fatalf("missing output, got %q", acc)
	}

	if _, err := inW.Write([]byte{detachByte}); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("attach did not return after detach")
	}
	_ = outW.Close()
	_ = inR.Close()
	_ = outR.Close()

	if err := CloseSession(ep, key, info.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCopyInputSendsWriteThenDetach(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &Conn{nc: a}

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan []protocol.Frame, 1)
	go func() {
		var frames []protocol.Frame
		for {
			f, err := protocol.ReadFrame(b)
			if err != nil {
				got <- frames
				return
			}
			frames = append(frames, f)
		}
	}()

	go func() {
		_, _ = inW.Write([]byte("xy"))
		_, _ = inW.Write([]byte{detachByte})
		_ = inW.Close()
	}()

	if err := copyInput(c, inR); !errors.Is(err, errUserDetach) {
		t.Fatalf("want detached, got %v", err)
	}
	_ = a.Close()

	var frames []protocol.Frame
	select {
	case frames = <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout reading frames")
	}
	if len(frames) < 2 {
		t.Fatalf("frames %+v", frames)
	}
	if frames[0].Type != protocol.TypeWrite || string(frames[0].Data) != "xy" {
		t.Fatalf("write frame %+v", frames[0])
	}
	if frames[1].Type != protocol.TypeDetach {
		t.Fatalf("detach frame %+v", frames[1])
	}
}

func TestWatchClientAPI(t *testing.T) {
	ep, key := startTestServer(t)
	info, err := Create(ep, key, CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- Attach(ep, key, info.ID, inR, outW)
	}()
	if _, err := inW.Write([]byte("echo watch-cli-ok\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var acc []byte
	buf := make([]byte, 1024)
	for time.Now().Before(deadline) {
		_ = outR.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := outR.Read(buf)
		if n > 0 {
			acc = append(acc, buf[:n]...)
			if bytes.Contains(acc, []byte("watch-cli-ok")) {
				break
			}
		}
		if err != nil && !os.IsTimeout(err) {
			t.Fatalf("read: %v", err)
		}
	}
	if _, err := inW.Write([]byte{detachByte}); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()
	<-errCh
	_ = outW.Close()
	_ = inR.Close()
	_ = outR.Close()

	if err := CloseSession(ep, key, info.ID); err != nil {
		t.Fatal(err)
	}
	listed, err := List(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range listed {
		if s.ID == info.ID && s.State == "CLOSED" {
			found = true
		}
	}
	if !found {
		t.Fatal("closed session should remain listed")
	}

	// Closed-session watch dumps ring then exits — exercises Watch() end-to-end.
	wOutR, wOutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	watchErr := make(chan error, 1)
	go func() {
		watchErr <- Watch(ep, key, info.ID, wOutW)
	}()
	deadline = time.Now().Add(5 * time.Second)
	acc = nil
	for time.Now().Before(deadline) {
		_ = wOutR.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := wOutR.Read(buf)
		if n > 0 {
			acc = append(acc, buf[:n]...)
		}
		select {
		case err := <-watchErr:
			_ = wOutW.Close()
			outRest, _ := io.ReadAll(wOutR)
			acc = append(acc, outRest...)
			_ = wOutR.Close()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(acc, []byte("watch-cli-ok")) {
				t.Fatalf("watch missing history: %q", acc)
			}
			return
		default:
		}
		if err != nil && !os.IsTimeout(err) {
			break
		}
	}
	t.Fatalf("watch did not finish; got %q", acc)
}

func TestDialContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, key, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, err = DialContext(ctx, Endpoint{Kind: transport.KindTLS, Address: "127.0.0.1:1", CertFP: strings.Repeat("a", 64)}, key)
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("want interrupted, got %v", err)
	}
}

func TestDrainPendingInput(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.Write([]byte("\n\n\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	drainPendingInput(r)
	buf := make([]byte, 8)
	_ = r.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	n, _ := r.Read(buf)
	if n != 0 {
		t.Fatalf("expected drained stdin, got %q", buf[:n])
	}
}

func TestDrainSignals(t *testing.T) {
	ch := make(chan os.Signal, 4)
	ch <- os.Interrupt
	ch <- os.Interrupt
	drainSignals(ch)
	select {
	case <-ch:
		t.Fatal("expected empty")
	default:
	}
}

func TestCopyOutputStopsOnDetach(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &Conn{nc: b}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- copyOutput(c, w)
	}()

	if err := protocol.WriteFrame(a, protocol.Frame{Type: protocol.TypeOutput, Data: []byte("hi")}); err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(a, protocol.Frame{Type: protocol.TypeDetached}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, errUserDetach) {
			t.Fatalf("copyOutput: want detached, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("copyOutput did not return")
	}
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hi" {
		t.Fatalf("got %q", out)
	}
}
