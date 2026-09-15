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
