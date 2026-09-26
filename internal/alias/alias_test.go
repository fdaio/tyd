package alias

import (
	"path/filepath"
	"testing"
)

func TestSetResolveRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aliases.json")

	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Set("jammy", "sess-1", "peer-a"); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, f); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Resolve("jammy") != "sess-1" {
		t.Fatalf("resolve=%q", loaded.Resolve("jammy"))
	}
	if loaded.Resolve("sess-1") != "sess-1" {
		t.Fatalf("raw id should pass through")
	}
	if loaded.NameFor("sess-1") != "jammy" {
		t.Fatalf("name=%q", loaded.NameFor("sess-1"))
	}

	// Re-alias same session replaces name.
	if err := loaded.Set("box", "sess-1", "peer-a"); err != nil {
		t.Fatal(err)
	}
	if loaded.Resolve("jammy") != "jammy" { // old name gone → treated as raw id
		t.Fatalf("old alias still resolves")
	}
	if loaded.Resolve("box") != "sess-1" {
		t.Fatalf("new alias=%q", loaded.Resolve("box"))
	}

	if err := loaded.Set("sess-1", "other", ""); err == nil {
		t.Fatal("alias name must not equal an existing session id target")
	}
	if err := loaded.Set("dup", "box", ""); err == nil {
		t.Fatal("session id must not be an alias name")
	}
	if err := loaded.Set("same", "same", ""); err == nil {
		t.Fatal("name must differ from session id")
	}

	if err := loaded.Remove("box"); err != nil {
		t.Fatal(err)
	}
	if loaded.NameFor("sess-1") != "" {
		t.Fatal("expected removed")
	}
}

func TestValidateName(t *testing.T) {
	if ValidateName("") == nil {
		t.Fatal("empty")
	}
	if ValidateName("bad name") == nil {
		t.Fatal("whitespace")
	}
	if ValidateName("ok") != nil {
		t.Fatal("ok should pass")
	}
}

func TestDropCorrupt(t *testing.T) {
	f := &File{Aliases: []Entry{
		{Name: "tama", SessionID: "tama"},
		{Name: "ok", SessionID: "sess-1"},
		{Name: "ghost", SessionID: "ok"}, // session_id is another alias name
	}}
	if !f.DropCorrupt() {
		t.Fatal("expected changes")
	}
	if len(f.Aliases) != 1 || f.Aliases[0].Name != "ok" || f.Aliases[0].SessionID != "sess-1" {
		t.Fatalf("%+v", f.Aliases)
	}
	if f.DropCorrupt() {
		t.Fatal("second drop should be no-op")
	}
}
