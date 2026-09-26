package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"tyd/internal/client"
	"tyd/internal/transport"
)

func TestEnsureLocalDaemonSkipsPeer(t *testing.T) {
	called := false
	old := startLocalDaemonFn
	startLocalDaemonFn = func(options) error {
		called = true
		return nil
	}
	t.Cleanup(func() { startLocalDaemonFn = old })

	opts := options{socket: filepath.Join(t.TempDir(), "missing.sock")}
	ep := client.Endpoint{Kind: transport.KindTLS, Address: "127.0.0.1:1"}
	if err := ensureLocalDaemon(opts, ep); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("must not start local daemon for peer TLS targets")
	}
}

func TestEnsureLocalDaemonNoopWhenReady(t *testing.T) {
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("tyd-ready-%d.sock", os.Getpid()))
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sock)
	})

	called := false
	old := startLocalDaemonFn
	startLocalDaemonFn = func(options) error {
		called = true
		return nil
	}
	t.Cleanup(func() { startLocalDaemonFn = old })

	opts := options{socket: sock}
	ep := client.Endpoint{Kind: transport.KindUnix, Address: sock}
	if err := ensureLocalDaemon(opts, ep); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("must not restart when socket already accepts")
	}
}

func TestEnsureLocalDaemonStartsWhenDown(t *testing.T) {
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("tyd-down-%d.sock", os.Getpid()))
	_ = os.Remove(sock)
	var ln net.Listener
	started := make(chan struct{}, 1)
	old := startLocalDaemonFn
	startLocalDaemonFn = func(opts options) error {
		if opts.socket != sock {
			t.Fatalf("socket=%q want %q", opts.socket, sock)
		}
		var err error
		ln, err = net.Listen("unix", sock)
		if err != nil {
			return err
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		started <- struct{}{}
		return nil
	}
	t.Cleanup(func() {
		startLocalDaemonFn = old
		if ln != nil {
			_ = ln.Close()
		}
		_ = os.Remove(sock)
	})

	opts := options{socket: sock}
	ep := client.Endpoint{Kind: transport.KindUnix, Address: sock}
	if err := ensureLocalDaemon(opts, ep); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	default:
		t.Fatal("expected startLocalDaemonFn to run")
	}
	if !localDaemonReady(sock) {
		t.Fatal("socket should be ready after ensure")
	}
}
