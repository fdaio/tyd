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
	"tyd/internal/peers"
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

// A dot in an alias name is a legal name that the `tyd <session>.<peer>`
// shortcut cannot parse, so the alias is stored and the cost is said out loud
// at the moment it is set — not later, at attach time, as a usage error.
func TestSessionAliasWarnsOnDotName(t *testing.T) {
	dir := t.TempDir()
	cli := options{
		sessions: filepath.Join(dir, "sessions.json"),
		recent:   filepath.Join(dir, "recent.json"),
		aliases:  filepath.Join(dir, "aliases.json"),
	}
	const sid, other = "29eef5de0d40c6d9", "878144071a28b83c"
	rememberSession(cli, catalog.Record{ID: sid, State: "ATTACHED", Addr: "/tmp/x.sock", CreatedAt: "2026-01-01T00:00:00Z"})
	rememberSession(cli, catalog.Record{ID: other, State: "ATTACHED", Addr: "/tmp/x.sock", CreatedAt: "2026-01-01T00:00:00Z"})

	runAliasArgs := func(rest ...string) (string, string) {
		t.Helper()
		opts := cli
		opts.rest = rest
		var err error
		var errOut string
		out := captureStdout(t, func() {
			errOut = captureStderr(t, func() { err = runAlias(opts) })
		})
		if err != nil {
			t.Fatal(err)
		}
		return out, errOut
	}

	out, errOut := runAliasArgs(sid, "tyd.cp")
	if !strings.Contains(out, "tyd.cp -> "+sid) {
		t.Fatalf("alias line missing: %q", out)
	}
	for _, want := range []string{"tyd.cp", "tyd <session>.<peer>", "tyd session attach tyd.cp"} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("warning missing %q: %q", want, errOut)
		}
	}
	if doc, _ := alias.Load(cli.aliases); doc.Resolve("tyd.cp") != sid {
		t.Fatal("a dotted alias is still a legal alias and must be stored")
	}

	// The `set` spelling warns the same way.
	_, errOut = runAliasArgs("set", other, "tyd.cp2")
	if !strings.Contains(errOut, "tyd session attach tyd.cp2") {
		t.Fatalf("set path warning: %q", errOut)
	}

	// A name without a dot keeps stderr exactly as it was.
	out, errOut = runAliasArgs(other, "jammy")
	if !strings.Contains(out, "jammy -> "+other) {
		t.Fatalf("alias line missing: %q", out)
	}
	if errOut != "" {
		t.Fatalf("plain alias must stay silent: %q", errOut)
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

// The PEER column used to print the raw peer id even when the operator had
// named that peer, while the same command showed session aliases. Prefer the
// nickname; never lose the id for a peer that has none.
func TestPeerLabelPrefersNickname(t *testing.T) {
	names := map[string]string{"d62c92f8452205d4": "osaka"}
	tests := []struct {
		id   string
		want string
	}{
		{"d62c92f8452205d4", "osaka"},
		{"92d09d9143b21eb8", "92d09d9143b21eb8"}, // unknown peer keeps its id
		{"", "-"},
	}
	for _, tc := range tests {
		if got := peerLabel(tc.id, names); got != tc.want {
			t.Errorf("peerLabel(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
	// No peers.json at all: ids, not an error and not "-".
	if got := peerLabel("abc", nil); got != "abc" {
		t.Errorf("peerLabel with no names = %q, want the id", got)
	}
}

func TestPeerNamesIgnoresUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "peers.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := peerNames(bad); len(got) != 0 {
		t.Errorf("corrupt peers.json = %v, want no names", got)
	}
	if got := peerNames(filepath.Join(dir, "missing.json")); len(got) != 0 {
		t.Errorf("missing peers.json = %v, want no names", got)
	}
}

// End to end: a named peer shows up by nickname, an unnamed one by id, and a
// missing peers.json leaves the list working.
func TestSessionListShowsPeerNickname(t *testing.T) {
	dir := t.TempDir()
	sessions := filepath.Join(dir, "sessions.json")
	peersPath := filepath.Join(dir, "peers.json")

	const named, unnamed = "d62c92f8452205d4", "92d09d9143b21eb8"
	if err := catalog.Save(sessions, &catalog.File{Sessions: []catalog.Record{
		{ID: "aaaaaaaaaaaaaaa", PeerID: named, State: "DETACHED", CreatedAt: "2026-09-28T08:46:06Z"},
		{ID: "bbbbbbbbbbbbbbb", PeerID: unnamed, State: "DETACHED", CreatedAt: "2026-09-27T05:15:13Z"},
	}}); err != nil {
		t.Fatal(err)
	}
	pdoc := &peers.File{Peers: []peers.Peer{
		{ID: named, Nickname: "osaka", Direction: "outbound"},
		{ID: unnamed, Direction: "outbound"},
	}}
	if err := peers.Save(peersPath, pdoc); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := run(options{
			cmd: "session", rest: []string{"list"},
			aliases: filepath.Join(dir, "aliases.json"), sessions: sessions,
			recent: filepath.Join(dir, "recent.json"), peers: peersPath,
			platform: "http://127.0.0.1:1",
		}); err != nil {
			t.Fatal(err)
		}
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("header and 2 rows, got:\n%s", out)
	}
	if !strings.Contains(lines[1], "osaka") || strings.Contains(lines[1], named) {
		t.Errorf("named peer row should show osaka, not %s: %q", named, lines[1])
	}
	if !strings.Contains(lines[2], unnamed) {
		t.Errorf("unnamed peer row should keep its id: %q", lines[2])
	}

	// Without a peers.json the list still renders, showing ids.
	out = captureStdout(t, func() {
		if err := run(options{
			cmd: "session", rest: []string{"list"},
			aliases: filepath.Join(dir, "aliases.json"), sessions: sessions,
			recent:   filepath.Join(dir, "recent.json"),
			platform: "http://127.0.0.1:1",
		}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, named) {
		t.Errorf("without peers.json the id should still show:\n%s", out)
	}
}
