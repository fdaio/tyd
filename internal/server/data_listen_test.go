package server

import (
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/session"
)

// A remembered data-plane port can be taken by the time the daemon starts
// again. The daemon must come up on an ephemeral port instead of failing.
func TestDataListenFallsBackWhenPreferredPortIsBusy(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	busy := pc.LocalAddr().String()

	dir := t.TempDir()
	// AF_UNIX paths are short; a temporary-directory path is not always.
	sock := fmt.Sprintf("/tmp/tyd-dl-%d.sock", time.Now().UnixNano())
	_, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewWithConfig(Config{
		Socket:             sock,
		DataListen:         busy,
		DataListenFallback: "127.0.0.1:0",
		CertPath:           filepath.Join(dir, "server.crt"),
		KeyPath:            filepath.Join(dir, "server.key"),
		Mgr:                session.NewManager(),
		Trust:              trust,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	got := srv.DataPlaneAddr()
	if got == "" {
		t.Fatal("no data-plane listener after the fallback")
	}
	if got == busy {
		t.Fatalf("data plane reused the busy address %s", got)
	}
}
