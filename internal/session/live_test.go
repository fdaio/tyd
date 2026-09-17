package session

import (
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/live"
)

func TestMain(m *testing.M) {
	if os.Getenv("TYD_TEST_LIVE_AGENT") == "1" {
		dir := os.Getenv("TYD_TEST_LIVE_DIR")
		if err := live.Run(dir); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testLiveStarter(t *testing.T) live.Starter {
	t.Helper()
	return func(_, dir string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(),
			"TYD_TEST_LIVE_AGENT=1",
			"TYD_TEST_LIVE_DIR="+dir,
		)
		logf, err := os.OpenFile(live.LogPath(dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		cmd.Stdout = logf
		cmd.Stderr = logf
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			_ = logf.Close()
			return nil, err
		}
		_ = logf.Close()
		return cmd, nil
	}
}

func TestLivePersistAcrossManagerRestart(t *testing.T) {
	root, err := os.MkdirTemp("", "tl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cwd, err := os.MkdirTemp("", "tc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cwd) })
	marker := filepath.Join(cwd, "alive")

	_, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ownerPub := auth.EncodePublic(priv.Public().(ed25519.PublicKey))

	m1 := NewManager()
	m1.ConfigureLive(root, "")
	m1.SetStarter(testLiveStarter(t))

	s, err := m1.Create(CreateOpts{
		Shell:    "/bin/sh",
		Cwd:      cwd,
		Owner:    "tester",
		OwnerPub: ownerPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := s.ID

	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	// Avoid matching PTY echo of the typed command: wait on a side-effect file.
	if _, err := att.Write([]byte("touch '" + marker + "'\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("shell did not create marker: %v", err)
	}
	att.Detach()

	// Graceful daemon stop: release without killing the agent.
	m1.Shutdown()

	if !live.Alive(live.Dir(root, sid)) {
		t.Fatal("live-agent died after Shutdown")
	}

	m2 := NewManager()
	m2.ConfigureLive(root, "")
	m2.SetStarter(testLiveStarter(t))
	restored, err := m2.RestoreLive()
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0].Session.ID != sid {
		t.Fatalf("restore=%v want id %s", restored, sid)
	}
	if restored[0].OwnerPub != ownerPub {
		t.Fatalf("owner pub %q", restored[0].OwnerPub)
	}

	trust := auth.NewStore()
	p := trust.EnsurePeer("tester", priv.Public().(ed25519.PublicKey), nil)
	if err := trust.Grant(priv.Public().(ed25519.PublicKey), sid, auth.OwnerCaps...); err != nil {
		t.Fatal(err)
	}
	if !trust.Allow(p, auth.CapAttach, sid) {
		t.Fatal("caps not restored")
	}

	s2, err := m2.Get(sid)
	if err != nil {
		t.Fatal(err)
	}
	att2, _, err := s2.Attach()
	if err != nil {
		t.Fatal(err)
	}
	marker2 := filepath.Join(cwd, "alive2")
	if _, err := att2.Write([]byte("touch '" + marker2 + "'\n")); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker2); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(marker2); err != nil {
		t.Fatalf("reattach shell did not create marker: %v", err)
	}
	att2.Detach()

	if err := m2.Close(sid); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && live.Alive(live.Dir(root, sid)) {
		time.Sleep(50 * time.Millisecond)
	}
	if live.Alive(live.Dir(root, sid)) {
		t.Fatal("agent still alive after Close")
	}
}

func TestLiveDeadAgentCleanedOnRestore(t *testing.T) {
	root, err := os.MkdirTemp("", "tl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	dir := live.Dir(root, "deadbeef")
	if err := live.SaveMeta(dir, live.Meta{
		ID:        "deadbeef",
		Owner:     "x",
		OwnerPub:  "yw==",
		Shell:     "/bin/sh",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Rows:      24,
		Cols:      80,
	}); err != nil {
		t.Fatal(err)
	}
	if err := live.WritePID(live.AgentPIDPath(dir), 1<<30); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	m.ConfigureLive(root, "")
	restored, err := m.RestoreLive()
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 0 {
		t.Fatalf("want no restore, got %d", len(restored))
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dead dir should be removed: %v", err)
	}
}

func TestInProcessCreateStillWorks(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()
	s, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	defer att.Detach()
	if _, err := att.Write([]byte("echo HI\n")); err != nil {
		t.Fatal(err)
	}
	var got []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, err := att.RecvTimeout(100 * time.Millisecond)
		if err == nil {
			got = append(got, b...)
			if strings.Contains(string(got), "HI") {
				return
			}
			continue
		}
		if !os.IsTimeout(err) {
			t.Fatal(err)
		}
	}
	t.Fatalf("got %q", got)
}
