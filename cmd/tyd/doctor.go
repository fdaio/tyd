package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"tyd/internal/auth"
	"tyd/internal/paths"
	"tyd/internal/peers"
	"tyd/internal/peerstate"
	"tyd/internal/safefile"
)

// lowDiskBytes is where a shrinking filesystem stops being someone else's
// problem: below this, the next state write is likely to fail.
const lowDiskBytes = 16 << 20

type checkLevel int

const (
	levelOK checkLevel = iota
	levelWarn
	levelFail
)

func (l checkLevel) tag() string {
	switch l {
	case levelWarn:
		return "warn"
	case levelFail:
		return "fail"
	default:
		return "ok"
	}
}

type check struct {
	level  checkLevel
	name   string
	detail string
}

// runDoctor reports on the files and disk tyd depends on, and with --fix
// rebuilds a peers.json that is missing or damaged.
func runDoctor(opts options) error {
	checks, fixable := doctorChecks(opts)
	worst := levelOK
	for _, c := range checks {
		fmt.Fprintf(os.Stdout, "%-4s %-16s %s\n", c.level.tag(), c.name, c.detail)
		if c.level > worst {
			worst = c.level
		}
	}
	if fixable && !opts.fix {
		fmt.Fprintln(os.Stderr, "\nrun tyd doctor --fix to rebuild peers.json from the Control Panel")
	}
	if fixable && opts.fix {
		fmt.Fprintln(os.Stderr)
		if err := doctorFixPeers(opts); err != nil {
			return err
		}
		return nil
	}
	if worst == levelFail {
		return fmt.Errorf("doctor found problems")
	}
	return nil
}

// doctorChecks inspects ~/.tyd and reports whether peers.json needs rebuilding.
func doctorChecks(opts options) (out []check, peersBroken bool) {
	dir := filepath.Dir(opts.peers)
	if st, err := os.Stat(dir); err != nil {
		out = append(out, check{levelFail, "state dir", fmt.Sprintf("%s: %v", dir, err)})
	} else {
		out = append(out, check{levelOK, "state dir", fmt.Sprintf("%s (mode %o)", dir, st.Mode().Perm())})
	}

	out = append(out, diskCheck(dir))
	out = append(out, writableCheck(dir))

	for _, f := range []struct {
		name     string
		path     string
		required bool
		parse    func(string) error
	}{
		{"identity", opts.identity, true, func(p string) error {
			_, err := auth.LoadIdentity(p)
			return err
		}},
		{"trust", opts.trust, false, func(p string) error {
			_, err := auth.LoadStore(p)
			return err
		}},
		{"peers", opts.peers, false, func(p string) error {
			_, err := peers.Load(p)
			return err
		}},
		{"aliases", opts.aliases, false, parseJSON},
		{"sessions", opts.sessions, false, parseJSON},
		{"recent", opts.recent, false, parseJSON},
	} {
		c, broken := fileCheck(f.name, f.path, f.required, f.parse)
		out = append(out, c)
		if f.name == "peers" && broken {
			peersBroken = true
		}
	}

	out = append(out, liveCheck(opts))
	return out, peersBroken
}

func diskCheck(dir string) check {
	free, err := diskFree(dir)
	if err != nil {
		return check{levelWarn, "disk", fmt.Sprintf("cannot stat filesystem: %v", err)}
	}
	detail := fmt.Sprintf("%s free on %s", humanBytes(free), dir)
	if free < lowDiskBytes {
		return check{levelFail, "disk", detail + " (writes will start failing)"}
	}
	return check{levelOK, "disk", detail}
}

func writableCheck(dir string) check {
	probe := filepath.Join(dir, ".doctor-probe")
	if err := safefile.WriteFile(probe, []byte("probe\n"), 0o600); err != nil {
		return check{levelFail, "writable", fmt.Sprintf("%s: %v", dir, err)}
	}
	_ = os.Remove(probe)
	return check{levelOK, "writable", dir}
}

func parseJSON(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var probe json.RawMessage
	return json.Unmarshal(b, &probe)
}

// fileCheck reports whether a state file is present and still usable, loading
// it the same way tyd does. The second result marks a file that exists but is
// damaged, which is what --fix can rebuild.
func fileCheck(name, path string, required bool, parse func(string) error) (check, bool) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		if required {
			return check{levelFail, name, path + ": missing"}, false
		}
		return check{levelOK, name, path + ": absent (not yet created)"}, false
	}
	if err != nil {
		return check{levelFail, name, fmt.Sprintf("%s: %v", path, err)}, false
	}
	if info.Size() == 0 {
		return check{levelFail, name, path + ": empty (truncated by a failed write?)"}, true
	}
	if parse != nil {
		if err := parse(path); err != nil {
			return check{levelFail, name, fmt.Sprintf("%s: %v", path, err)}, true
		}
	}
	return check{levelOK, name, fmt.Sprintf("%s (%s)", path, humanBytes(uint64(info.Size())))}, false
}

func liveCheck(opts options) check {
	root := opts.live
	if root == "" {
		root = paths.DefaultLive()
	}
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return check{levelOK, "live sessions", "none"}
	}
	if err != nil {
		return check{levelWarn, "live sessions", fmt.Sprintf("%s: %v", root, err)}
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			n++
		}
	}
	return check{levelOK, "live sessions", fmt.Sprintf("%d agent dir(s) under %s", n, root)}
}

// doctorFixPeers sets a damaged peers.json aside and rebuilds it from the CP.
func doctorFixPeers(opts options) error {
	if _, err := os.Stat(opts.peers); err == nil {
		target, err := quarantineFile(opts.peers)
		if err != nil {
			return fmt.Errorf("set aside %s: %w", opts.peers, err)
		}
		fmt.Fprintf(os.Stderr, "moved damaged file to %s\n", target)
	}
	state := peerstate.New(opts.peers, nil)
	if err := recoverRegistration(opts, state); err != nil {
		return fmt.Errorf("recover from control panel: %w", err)
	}
	fmt.Fprintf(os.Stderr, "rebuilt %s; restart tyd up\n", opts.peers)
	return nil
}

func diskFree(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	// Field widths and signedness vary across the BSDs and Linux.
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
