package policy

import (
	"os"
	"path/filepath"
	"testing"

	"tyd/internal/auth"
)

func tempPolicy(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "policy.json")
}

func TestEnsureMigratesExistingPeers(t *testing.T) {
	path := tempPolicy(t)
	f, err := Ensure(path, []string{"peer-a", "peer-b"})
	if err != nil {
		t.Fatal(err)
	}
	if f.DefaultRole != RoleList {
		t.Errorf("default = %q, want list", f.DefaultRole)
	}
	if got := f.RoleFor("peer-a"); got != RoleOperator {
		t.Errorf("existing peer role = %q, want operator", got)
	}
	if got := f.RoleFor("new-peer"); got != RoleList {
		t.Errorf("new peer role = %q, want list", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestEnsureKeepsAnExistingFile(t *testing.T) {
	path := tempPolicy(t)
	f, err := Ensure(path, []string{"peer-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Set("peer-a", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	again, err := Ensure(path, []string{"peer-a", "peer-b"})
	if err != nil {
		t.Fatal(err)
	}
	if got := again.RoleFor("peer-a"); got != RoleViewer {
		t.Errorf("role = %q, want viewer", got)
	}
	if got := again.RoleFor("peer-b"); got != RoleList {
		t.Errorf("new peer in existing file = %q, want list", got)
	}
}

func TestCorruptPolicyIsAnError(t *testing.T) {
	path := tempPolicy(t)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(path, nil); err == nil {
		t.Fatal("accepted a corrupt policy")
	}
}

func TestSetRejectsUnknownRole(t *testing.T) {
	f := &File{DefaultRole: RoleList}
	if err := f.Set("peer-a", Role("root")); err == nil {
		t.Fatal("accepted an unknown role")
	}
}

func TestCaps(t *testing.T) {
	cases := []struct {
		role Role
		want []auth.Cap
	}{
		{RoleList, []auth.Cap{auth.CapList}},
		{RoleViewer, []auth.Cap{auth.CapList, auth.CapWatchAny, auth.CapReadAny}},
		{RoleOperator, []auth.Cap{auth.CapList, auth.CapCreate}},
		{RoleAdmin, []auth.Cap{auth.CapList, auth.CapCreate, auth.CapWatchAny, auth.CapReadAny}},
	}
	for _, tc := range cases {
		got, err := Caps(tc.role)
		if err != nil {
			t.Fatalf("%s: %v", tc.role, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%s: caps = %v, want %v", tc.role, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: caps = %v, want %v", tc.role, got, tc.want)
			}
		}
	}
	if _, err := Caps("root"); err == nil {
		t.Fatal("accepted an unknown role")
	}
}
