package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tyd/internal/alias"
	"tyd/internal/auth"
	"tyd/internal/catalog"
	"tyd/internal/client"
	"tyd/internal/server"
	"tyd/internal/session"
)

func TestRunRejectsBadUsage(t *testing.T) {
	dir := t.TempDir()
	base := options{
		socket: "/tmp/x.sock", identity: "/tmp/id", trust: "/tmp/t.json", listen: "off",
		recent: filepath.Join(dir, "recent.json"), aliases: filepath.Join(dir, "aliases.json"),
	}

	a := base
	a.cmd = "session"
	a.rest = []string{"attach"}
	if err := run(a); err == nil {
		t.Fatal("attach without id and without recent")
	}
	c := base
	c.cmd = "session"
	c.rest = []string{"close"}
	if err := run(c); err == nil {
		t.Fatal("close without id and without recent")
	}
	w := base
	w.cmd = "wat"
	if err := run(w); err == nil {
		t.Fatal("unknown command")
	}
	legacy := base
	legacy.cmd = "create"
	if err := run(legacy); err == nil || !strings.Contains(err.Error(), "tyd session create") {
		t.Fatalf("expected migration hint, got %v", err)
	}
}

func TestRunSessionCreateListStatusClose(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id_ed25519")
	trustPath := filepath.Join(dir, "trusted.json")
	_, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.WriteIdentity(idPath, priv); err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := auth.WriteBootstrapTrust(trustPath, "local", pub); err != nil {
		t.Fatal(err)
	}
	trust, err := auth.LoadStore(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	sock := fmt.Sprintf("/tmp/tyd-main-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	srv := server.NewWithConfig(server.Config{
		Socket: sock, Listen: "off", Mgr: session.NewManager(), Trust: trust,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	cli := options{
		socket: sock, identity: idPath, trust: trustPath, listen: "off",
		recent: filepath.Join(dir, "recent.json"), aliases: filepath.Join(dir, "aliases.json"),
		sessions: filepath.Join(dir, "sessions.json"),
	}
	id := strings.TrimSpace(captureStdout(t, func() {
		create := cli
		create.cmd = "session"
		create.rest = []string{"create"}
		create.detach = true
		if err := run(create); err != nil {
			t.Fatal(err)
		}
	}))
	if id == "" {
		t.Fatal("empty session id")
	}
	listOut := captureStdout(t, func() {
		list := cli
		list.cmd = "session"
		list.rest = []string{"list"}
		if err := run(list); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(listOut, id) {
		t.Fatalf("list missing id: %q", listOut)
	}
	out := captureStdout(t, func() {
		st := cli
		st.cmd = "status"
		if err := run(st); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "TRANSPORT") {
		t.Fatalf("status missing connections header: %q", out)
	}
	if !strings.Contains(out, "Control Panel") {
		t.Fatalf("status missing CP section: %q", out)
	}
	closeCmd := cli
	closeCmd.cmd = "session"
	closeCmd.rest = []string{"close", id}
	if err := run(closeCmd); err != nil {
		t.Fatal(err)
	}

	aliasCmd := cli
	aliasCmd.cmd = "alias"
	aliasCmd.rest = []string{id, "jammy"}
	outAlias := captureStdout(t, func() {
		if err := run(aliasCmd); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(outAlias, "jammy ->") {
		t.Fatalf("alias out %q", outAlias)
	}
	list2 := captureStdout(t, func() {
		list := cli
		list.cmd = "session"
		list.rest = []string{"list"}
		if err := run(list); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(list2, "jammy") {
		t.Fatalf("list missing alias column: %q", list2)
	}
	closeAlias := cli
	closeAlias.cmd = "session"
	closeAlias.rest = []string{"close", "jammy"}

	alist := captureStdout(t, func() {
		a := cli
		a.cmd = "alias"
		a.rest = nil
		if err := run(a); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(alist, "jammy") || !strings.Contains(alist, id) {
		t.Fatalf("alias list %q", alist)
	}
}

func TestTopLevelAliasDeprecationNote(t *testing.T) {
	dir := t.TempDir()
	opts := options{
		cmd: "alias", rest: []string{"list"},
		aliases: filepath.Join(dir, "aliases.json"),
		recent:  filepath.Join(dir, "recent.json"),
	}
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	errRun := run(opts)
	_ = w.Close()
	os.Stderr = old
	if errRun != nil {
		t.Fatal(errRun)
	}
	b, _ := io.ReadAll(r)
	note := string(b)
	if !strings.Contains(note, "prefer 'tyd session alias'") {
		t.Fatalf("missing deprecation note: %q", note)
	}
}

func TestWriteSessionListPlainHidesSize(t *testing.T) {
	var buf bytes.Buffer
	writeSessionList(&buf, []sessionListRow{
		{ID: "aaa", Alias: "amy", Peer: "-", State: "DETACHED", Created: "2026-09-16T07:44:54Z"},
		{ID: "bbb", Alias: "", Peer: "-", State: "CLOSED", Created: "2026-09-16T06:37:33Z"},
	}, false)
	out := buf.String()
	if strings.Contains(out, "SIZE") || strings.Contains(out, "PID") || strings.Contains(out, "\033[") {
		t.Fatalf("plain list: %q", out)
	}
	if !strings.Contains(out, "SESSION") || !strings.Contains(out, "ALIAS") || !strings.Contains(out, "STATE") || !strings.Contains(out, "PEER") || !strings.Contains(out, "CREATED") {
		t.Fatalf("missing headers: %q", out)
	}
	if !strings.Contains(out, "2026-09-16T07:44:54Z") {
		t.Fatalf("missing created: %q", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines=%d %q", len(lines), out)
	}
}

func TestWriteSessionListColorAliasAndLiveState(t *testing.T) {
	var buf bytes.Buffer
	writeSessionList(&buf, []sessionListRow{
		{ID: "aaa", Alias: "amy", Peer: "-", State: "DETACHED", Created: "t"},
		{ID: "bbb", Alias: "", Peer: "-", State: "CLOSED", Created: "t"},
		{ID: "ccc", Alias: "", Peer: "-", State: "PENDING", Created: "t"},
		{ID: "ddd", Alias: "", Peer: "-", State: "ATTACHED", Created: "t"},
	}, true)
	out := buf.String()
	header := strings.Split(out, "\n")[0]
	if strings.Contains(header, ansiCyan) {
		t.Fatalf("headers must be plain: %q", header)
	}
	if !strings.Contains(out, ansiCyan+"amy") {
		t.Fatalf("alias should be cyan: %q", out)
	}
	if !strings.Contains(out, ansiCyan+"ATTACHED") {
		t.Fatalf("ATTACHED should be cyan: %q", out)
	}
	for _, st := range []string{"DETACHED", "PENDING", "CLOSED"} {
		if strings.Contains(out, ansiCyan+st) {
			t.Fatalf("%s must not be cyan: %q", st, out)
		}
	}
}

func TestSessionListIsLocalCatalog(t *testing.T) {
	dir := t.TempDir()
	aliases := filepath.Join(dir, "aliases.json")
	sessions := filepath.Join(dir, "sessions.json")
	adoc := &alias.File{}
	if err := adoc.Set("amy", "878144071a28b83c", "8a6592c332eba2b2"); err != nil {
		t.Fatal(err)
	}
	if err := alias.Save(aliases, adoc); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		err := run(options{
			cmd: "session", rest: []string{"list"},
			aliases: aliases, sessions: sessions, recent: filepath.Join(dir, "recent.json"),

			platform: "http://127.0.0.1:1",
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "878144071a28b83c") || !strings.Contains(out, "amy") {
		t.Fatalf("local list: %q", out)
	}
}

func TestFinishStreamRecordsExited(t *testing.T) {
	dir := t.TempDir()
	cli := options{
		sessions: filepath.Join(dir, "sessions.json"),
		recent:   filepath.Join(dir, "recent.json"),
		aliases:  filepath.Join(dir, "aliases.json"),
	}
	const sid = "exited-session"
	rememberSession(cli, catalog.Record{ID: sid, State: "ATTACHED", Addr: "/tmp/x.sock", CreatedAt: "2026-01-01T00:00:00Z"})

	// Unrelated errors pass through untouched.
	want := errors.New("boom")
	if got := finishStream(cli, sid, want); !errors.Is(got, want) {
		t.Fatalf("error should pass through, got %v", got)
	}
	if rec, _ := loadLocalCatalog(cli).Get(sid); rec.State != "ATTACHED" {
		t.Fatalf("state changed on a normal error: %s", rec.State)
	}

	// A shell exit is a success, and the catalog records the new state.
	if got := finishStream(cli, sid, client.ErrShellExited); got != nil {
		t.Fatalf("shell exit must not fail the CLI, got %v", got)
	}
	rec, ok := loadLocalCatalog(cli).Get(sid)
	if !ok {
		t.Fatal("session vanished from the catalog")
	}
	if rec.State != string(session.StateExited) {
		t.Fatalf("state=%s want EXITED", rec.State)
	}
	if rec.Addr != "/tmp/x.sock" {
		t.Fatalf("endpoint info lost: %q", rec.Addr)
	}

	// Unknown ids are ignored rather than creating a record.
	if got := finishStream(cli, "no-such-session", client.ErrShellExited); got != nil {
		t.Fatalf("got %v", got)
	}
	if _, ok := loadLocalCatalog(cli).Get("no-such-session"); ok {
		t.Fatal("should not invent a catalog record")
	}
}
