package client

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"tyd/internal/protocol"
	"tyd/internal/server"
	"tyd/internal/session"
)

func startTestServer(t *testing.T) string {
	t.Helper()
	sock := fmt.Sprintf("/tmp/tyd-cli-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	srv := server.New(sock, session.NewManager())
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if err := WaitSocket(sock, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	return sock
}

func TestDialMissingSocket(t *testing.T) {
	_, err := Dial("/tmp/tyd-does-not-exist.sock")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateListClose(t *testing.T) {
	sock := startTestServer(t)
	info, err := Create(sock, CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir(), Rows: 0, Cols: 0})
	if err != nil {
		t.Fatal(err)
	}
	if info.ID == "" || info.PID == 0 {
		t.Fatalf("incomplete session: %+v", info)
	}
	if info.Rows != 24 || info.Cols != 80 {
		t.Fatalf("default size %dx%d", info.Cols, info.Rows)
	}

	listed, err := List(sock)
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

	if err := CloseSession(sock, info.ID); err != nil {
		t.Fatal(err)
	}
	listed, err = List(sock)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range listed {
		if s.ID == info.ID {
			t.Fatal("closed session still listed")
		}
	}
}

func TestCreateWithoutServer(t *testing.T) {
	_, err := Create("/tmp/tyd-no-server.sock", CreateOpts{})
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

func TestAttachWriteAndDetach(t *testing.T) {
	sock := startTestServer(t)
	info, err := Create(sock, CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
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
		errCh <- Attach(sock, info.ID, inR, outW)
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

	if err := CloseSession(sock, info.ID); err != nil {
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

	if err := copyInput(c, inR); err != nil {
		t.Fatal(err)
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
		if err != nil {
			t.Fatal(err)
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
