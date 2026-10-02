package fileroot

import "strings"

// The sensitive-path list. **Defence in depth, not a boundary** — a model with a
// shell can read all of this by other means, and the root restriction is about the
// file tools.
//
// Decided **lexically, by name, before anything is opened.** That ordering is the
// point: deciding after an open would make "refused because it is sensitive" differ
// from "refused because it is missing", and that difference tells a caller whether
// a path exists. Here, a refused path has not been looked for.
//
// On by default in this version, with no switch.

// writeBlocked are path prefixes and names refused for writing. These are the ones
// that turn a write into code execution: a git hook runs on the next git command, a
// shell startup file runs on the next shell, and an authorized key is a login.
var writeBlocked = []string{
	".git/hooks/",
	".git/config",
	".ssh/",
	".gnupg/",
	".aws/",
	".config/gcloud/",
	".kube/",
}

// writeBlockedNames are refused wherever they appear, because a shell reads them
// from several directories and a startup file is a bare name.
var writeBlockedNames = []string{
	".bashrc", ".bash_profile", ".bash_login", ".profile",
	".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout",
	".cshrc", ".tcshrc",
	".env",
}

// readBlocked are refused for reading. Narrower than the write list on purpose: a
// read cannot become code execution, and a list long enough to be thorough starts
// refusing files a model legitimately needs — which is how a deny list gets turned
// off wholesale.
var readBlocked = []string{
	".ssh/",
	".gnupg/",
	".aws/credentials",
	".config/gcloud/",
	".kube/config",
}

// readBlockedNames match exactly rather than as a glob. A `.env*` glob would refuse
// `.env.example`, and a project full of those trains people to disable the check.
var readBlockedNames = []string{
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity",
}

// blocked reports whether rel is refused for this operation.
func blocked(rel string, write bool) bool {
	rel = strings.ToLower(rel)
	parts := strings.Split(rel, "/")
	base := parts[len(parts)-1]

	prefixes := readBlocked
	names := readBlockedNames
	if write {
		prefixes = writeBlocked
		names = writeBlockedNames
	}

	// A prefix is matched on whole components, so `.ssh/` does not also refuse
	// `.sshconfig`, and `x/.ssh/y` is caught because the components line up.
	for _, prefix := range prefixes {
		segments := strings.Split(strings.TrimSuffix(prefix, "/"), "/")
		if hasComponents(parts, segments) {
			return true
		}
	}
	for _, name := range names {
		if base == name {
			return true
		}
	}
	return false
}

// hasComponents reports whether want appears as consecutive components of parts.
func hasComponents(parts, want []string) bool {
	if len(want) == 0 || len(want) > len(parts) {
		return false
	}
	for i := 0; i+len(want) <= len(parts); i++ {
		ok := true
		for j, w := range want {
			if parts[i+j] != w {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
