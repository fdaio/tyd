// Package fileroot gives a caller one directory to read and write beneath, and
// nothing above it.
//
// What it does **not** do is stop the caller reaching anything else. A model with
// session_send has a shell, and the shell reaches wherever the daemon's user
// reaches. This is not a sandbox. What it protects is narrower and is the only
// thing worth protecting: the operator approved a write to foo/bar.txt, and when
// the write happens it is that file and not somewhere a symlink now points.
//
// Path resolution is [os.Root]'s. It refuses any component that resolves outside
// the root, which is unconditional and comes from the standard library rather than
// from here. What this package adds is everything os.Root deliberately leaves to a
// caller: deciding a path is refused *by name* before anything is opened, capping
// sizes, preserving permissions on a descriptor rather than a path, and the write
// sequence that leaves the original untouched if any step fails.
package fileroot

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"
)

// Code is the error vocabulary. The caller maps these onto whatever it reports to
// a model, and the distinctions exist because the fix differs: retrying is sensible
// for one and pointless for another.
type Code string

const (
	// CodeOutsideRoot: the path resolved above the root.
	CodeOutsideRoot Code = "outside_root"
	// CodeBlockedPath: refused by the sensitive-path list, decided by name.
	CodeBlockedPath Code = "blocked_path"
	// CodeNotFound: nothing there.
	CodeNotFound Code = "not_found"
	// CodeExists: a create where the file already is.
	CodeExists Code = "exists"
	// CodeNotRegular: a directory, a FIFO or a device.
	CodeNotRegular Code = "not_regular"
	// CodeTooLarge: over one of the caps.
	CodeTooLarge Code = "too_large"
	// CodeConflict: expected_sha256 did not match what is there.
	CodeConflict Code = "conflict"
	// CodeUnavailable: the root itself is unusable.
	CodeUnavailable Code = "unavailable"
	// CodeSymlink: the last component is a symlink.
	//
	// Added after implementing. The design's table had no name for it because it
	// assumed os.Root refused a symlinked final component, which it does not — see
	// openLastNoFollow. A symlink is not "not_regular" (it resolves to one) and not
	// "blocked_path" (it is not on the sensitive list), and an operator seeing
	// either of those would look in the wrong place.
	CodeSymlink Code = "symlink"
	// CodeDenied: the daemon's own user cannot read or write it.
	//
	// Also added after implementing, and for the same reason the table separates
	// codes at all: an operator fixes this with a chmod, not by retrying or by
	// changing what the tool is allowed to reach.
	CodeDenied Code = "denied"
)

// Error carries a Code and never an absolute path. A path above the root is
// reported as the root-relative form the caller passed, so an error cannot be used
// to discover the shape of the filesystem outside.
type Error struct {
	Code Code
	// Path is the root-relative path, cleaned. It is empty for CodeUnavailable.
	Path string
	Err  error
}

func (e *Error) Error() string {
	if e.Path == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Path)
}

func (e *Error) Unwrap() error { return e.Err }

// CodeOf returns the code for an error, or "" if it is not one of ours.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func fail(code Code, p string, err error) error {
	return &Error{Code: code, Path: clean(p), Err: err}
}

// Size caps. A read's default is small because a model asking for a file wants the
// file; the hard ceiling is what stops a mistake from becoming an allocation.
const (
	DefaultReadBytes = 64 << 10
	MaxReadBytes     = 1 << 20
	MaxWriteBytes    = 1 << 20
)

// MaxPathLen and MaxRootLen bound the path and the root claim.
//
// Not for tidiness. A path and a root claim travel in the same frame as the content,
// so their length decides how much of the frame is left for content — and
// PATH_MAX-sized paths plus PATH_MAX-sized roots overflow the frame by a couple of
// hundred bytes, which the sender cannot see and the receiver cannot report. So the
// length the protocol reserves is derived from a bound this package **enforces**,
// rather than from whatever the filesystem happens to allow.
//
// 1024 is far longer than any path inside a project tree, and short enough that the
// two together leave the frame's payload room.
const (
	MaxPathLen = 1024
	MaxRootLen = 1024
)

// WriteMode says what the target must be for the write to go ahead.
type WriteMode string

const (
	// ModeCreate fails if the target exists. It never truncates: "create" that
	// overwrites is a data-loss bug wearing a helpful name.
	ModeCreate WriteMode = "create"
	// ModeReplace fails if the target does not exist, or is not a regular file.
	ModeReplace WriteMode = "replace"
)

// Root is an open directory. It holds a descriptor, not a path: if the directory is
// moved or renamed, operations still reach it. It is safe for concurrent use.
type Root struct {
	r *os.Root
	// dir is the path as it was opened, for messages only. Nothing resolves
	// through it.
	dir string
}

// Open takes a directory descriptor for dir.
//
// This does **not** refuse `/` or `$HOME`. That decision belongs to whoever
// configures the root — the daemon's `--file-root`, where an operator can see it and
// override it deliberately — and a check here would be a second copy of a rule that
// lives in configuration, which is how the two drift apart.
//
// The library's job is to make the root mean something once it exists: nothing above
// it is reachable, whatever the caller asks for.
func Open(dir string) (*Root, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fail(CodeUnavailable, "", err)
	}
	if !info.IsDir() {
		return nil, fail(CodeUnavailable, "", fmt.Errorf("not a directory: %s", dir))
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fail(CodeUnavailable, "", err)
	}
	return &Root{r: r, dir: dir}, nil
}

// Dir is the directory as it was opened, for messages. Operations do not go
// through it.
func (r *Root) Dir() string { return r.dir }

// Narrow returns a Root for a directory inside this one.
//
// **This can only narrow.** It is [os.Root.OpenRoot], so the result is confined by
// this Root: a name that resolves outside is refused by the standard library rather
// than by a prefix comparison written here. That matters because a prefix test gets
// the awkward cases wrong — a sibling called `root-evil` starts with `root`, and a
// symlink named `inside` can point out — and the point of using os.Root is that
// those cases stop being ours to get right.
//
// name is relative to this Root, exactly as the operation's path is.
func (r *Root) Narrow(name string) (*Root, error) {
	rel := clean(name)
	if rel == "" || rel == "." {
		// The ceiling itself, re-opened, so a caller gets an independent
		// descriptor rather than a second handle onto the same one.
		sub, err := r.r.OpenRoot(".")
		if err != nil {
			return nil, fail(CodeOutsideRoot, rel, err)
		}
		return &Root{r: sub, dir: r.dir}, nil
	}
	if strings.HasPrefix(name, "/") {
		return nil, fail(CodeOutsideRoot, rel, errors.New("absolute path"))
	}
	if len(name) > MaxRootLen {
		return nil, fail(CodeTooLarge, rel, fmt.Errorf("root claim is %d bytes, above the %d ceiling", len(name), MaxRootLen))
	}
	sub, err := r.r.OpenRoot(rel)
	if err != nil {
		// An escape arrives as a permission error from os.Root, same as anywhere
		// else, so the code is the same: outside_root.
		if errors.Is(err, os.ErrPermission) {
			return nil, fail(CodeOutsideRoot, rel, nil)
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil, fail(CodeNotFound, rel, nil)
		}
		return nil, fail(CodeNotFound, rel, err)
	}
	return &Root{r: sub, dir: path.Join(r.dir, rel)}, nil
}

// Close releases the descriptor. The Root is unusable afterwards.
func (r *Root) Close() error { return r.r.Close() }

// ReadResult is one page of a file.
type ReadResult struct {
	// Data is the bytes read. They are raw: no cleaner, no escape processing, no
	// terminal semantics. A file read is not a terminal read.
	Data []byte
	// Size is the file's full size, so a caller can tell a short file from a
	// truncated one.
	Size int64
	// Truncated says the cap cut this result.
	Truncated bool
	// MTime is the file's modification time.
	MTime time.Time
	// SHA256 is the hex digest of the **whole** file, computed by reading past the
	// cap. A caller that wants a hash has one whether or not it read everything,
	// which is what makes expected_sha256 usable as a concurrency guard.
	SHA256 string
}

// Read returns bytes from offset, capped at maxBytes (or DefaultReadBytes when
// zero).
func (r *Root) Read(name string, offset int64, maxBytes int) (ReadResult, error) {
	rel, err := r.check(name, false)
	if err != nil {
		return ReadResult{}, err
	}
	if maxBytes <= 0 {
		maxBytes = DefaultReadBytes
	}
	if maxBytes > MaxReadBytes {
		return ReadResult{}, fail(CodeTooLarge, rel, fmt.Errorf("max_bytes above the %d ceiling", MaxReadBytes))
	}

	f, err := openRegular(r.r, rel)
	if err != nil {
		// Passed through, not re-mapped: openRegular already decided the code, and
		// mapping a coded error a second time turns every distinct outcome into one.
		return ReadResult{}, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return ReadResult{}, fail(CodeUnavailable, rel, err)
	}

	// The hash covers the whole file, so it is computed by streaming past the cap
	// rather than from what the caller is about to be handed.
	sum, err := r.digest(rel, f)
	if err != nil {
		return ReadResult{}, err
	}

	if offset < 0 {
		offset = 0
	}
	if offset > info.Size() {
		offset = info.Size()
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return ReadResult{}, fail(CodeUnavailable, rel, err)
	}

	buf := make([]byte, maxBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return ReadResult{}, fail(CodeUnavailable, rel, err)
	}
	return ReadResult{
		Data:      buf[:n],
		Size:      info.Size(),
		Truncated: offset+int64(n) < info.Size(),
		MTime:     info.ModTime().UTC(),
		SHA256:    sum,
	}, nil
}

// digest hashes the whole file through an already-open descriptor.
func (r *Root) digest(rel string, f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", fail(CodeUnavailable, rel, err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fail(CodeUnavailable, rel, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteResult is what a write did.
type WriteResult struct {
	// Written is the byte count.
	Written int
	// Created says the target did not exist before.
	Created bool
	// SHA256 is the hex digest of what was written.
	SHA256 string
	// Mode is the mode the file ended up with.
	Mode os.FileMode
}

// Write replaces or creates a file beneath the root.
//
// The sequence is the point. A temporary file in the target's own directory is
// written, flushed, given the target's permissions **on its own descriptor**, and
// only then renamed over the target — so a failure anywhere leaves the original
// exactly as it was, and a reader never sees a half-written file.
func (r *Root) Write(name string, content []byte, mode WriteMode, expectedSHA string) (WriteResult, error) {
	rel, err := r.check(name, true)
	if err != nil {
		return WriteResult{}, err
	}
	if len(content) > MaxWriteBytes {
		return WriteResult{}, fail(CodeTooLarge, rel,
			fmt.Errorf("%d bytes above the %d ceiling", len(content), MaxWriteBytes))
	}
	switch mode {
	case ModeCreate, ModeReplace:
	default:
		// Not one of the codes in §8: an unknown mode is a caller bug, not a
		// condition of a path or a file, and forcing it into the vocabulary would
		// report it to a model as though the filesystem were at fault.
		return WriteResult{}, fmt.Errorf("fileroot: unknown write mode %q", mode)
	}

	target, err := r.statTarget(rel, mode)
	if err != nil {
		return WriteResult{}, err
	}

	// The concurrency guard, checked against what is there rather than what was
	// there a moment ago. It narrows the window; it does not close it, and the
	// design says so.
	if expectedSHA != "" {
		if target.exists {
			got, err := r.fileDigest(rel)
			if err != nil {
				return WriteResult{}, err
			}
			if !strings.EqualFold(got, expectedSHA) {
				return WriteResult{}, fail(CodeConflict, rel,
					fmt.Errorf("expected %s, found %s", short(expectedSHA), short(got)))
			}
		} else if mode == ModeReplace {
			return WriteResult{}, fail(CodeNotFound, rel, nil)
		}
	}

	dir, base := path.Split(rel)
	if dir == "" {
		dir = "."
	}
	tmpName := "." + base + ".tyd-tmp"
	tmpRel := path.Join(dir, tmpName)

	tmp, err := r.r.OpenFile(tmpRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// A leftover from a crash. Replacing it is safe: the name is ours, it
			// is in the target's directory, and the real target is untouched by this.
			_ = r.r.Remove(tmpRel)
			tmp, err = r.r.OpenFile(tmpRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		}
		if err != nil {
			return WriteResult{}, fail(writeCode(err), rel, err)
		}
	}
	tmpName2 := tmpRel
	defer func() {
		// Only reached while unwinding or after a failed rename: the name is
		// cleared once the rename succeeds, so this cannot delete the real file.
		tmp.Close()
		_ = r.r.Remove(tmpName2)
	}()

	perm := os.FileMode(0o644)
	if target.exists {
		perm = target.mode.Perm()
	}
	if err := tmp.Chmod(perm); err != nil {
		return WriteResult{}, fail(CodeUnavailable, rel, err)
	}
	// Owner on the descriptor. A failure is not fatal: an unprivileged process
	// cannot always chown, and refusing the write over it would be worse than a file
	// the operator can fix with one command.
	if target.exists && target.uid >= 0 {
		_ = tmp.Chown(target.uid, target.gid)
	}

	if _, err := tmp.Write(content); err != nil {
		return WriteResult{}, fail(CodeUnavailable, rel, err)
	}
	// Before the rename, so a crash cannot publish an empty or partial file.
	if err := tmp.Sync(); err != nil {
		return WriteResult{}, fail(CodeUnavailable, rel, err)
	}
	info, err := tmp.Stat()
	if err != nil {
		return WriteResult{}, fail(CodeUnavailable, rel, err)
	}
	if err := tmp.Close(); err != nil {
		return WriteResult{}, fail(CodeUnavailable, rel, err)
	}
	if err := r.r.Rename(tmpRel, rel); err != nil {
		return WriteResult{}, fail(writeCode(err), rel, err)
	}
	// Past this point the temporary file is gone; the deferred remove must not run
	// against a name that no longer belongs to us.
	tmpName2 = ""

	// Persist the rename itself. Best effort: failing here costs durability, not
	// correctness, which is the same trade safefile makes.
	if d, err := r.r.OpenFile(dir, os.O_RDONLY, 0); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	sum := sha256.Sum256(content)
	return WriteResult{
		Written: len(content),
		Created: !target.exists,
		SHA256:  hex.EncodeToString(sum[:]),
		Mode:    info.Mode().Perm(),
	}, nil
}

type targetInfo struct {
	exists bool
	mode   os.FileMode
	uid    int
	gid    int
}

// statTarget looks at what is there, and refuses the combinations the mode forbids.
//
// **Lstat, not Stat.** Stat would resolve a symlink and report the target, so a
// write to `link` would be approved as a write to whatever it points at — and, for a
// dangling link, as a create. Lstat reports the link itself, which is the thing the
// caller named.
func (r *Root) statTarget(rel string, mode WriteMode) (targetInfo, error) {
	info, err := r.r.Lstat(rel)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if mode == ModeReplace {
				return targetInfo{}, fail(CodeNotFound, rel, nil)
			}
			return targetInfo{}, nil
		}
		return targetInfo{}, fail(writeCode(err), rel, err)
	}
	// A symlink at the target is refused rather than replaced. The rename below would
	// not follow it — it swaps the entry — so nothing would escape; but silently
	// destroying a link somebody put there is not what "write to this path" means.
	if info.Mode()&fs.ModeSymlink != 0 {
		return targetInfo{}, fail(CodeSymlink, rel, nil)
	}
	if mode == ModeCreate {
		return targetInfo{}, fail(CodeExists, rel, nil)
	}
	if !info.Mode().IsRegular() {
		return targetInfo{}, fail(CodeNotRegular, rel, nil)
	}
	uid, gid := ownerOf(info)
	return targetInfo{exists: true, mode: info.Mode(), uid: uid, gid: gid}, nil
}

func (r *Root) fileDigest(rel string) (string, error) {
	f, err := openRegular(r.r, rel)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return r.digest(rel, f)
}

// check applies the rules that do not need the filesystem: the sensitive-path
// decision, made by name, and the shape of the path.
//
// **Lexical and before anything is opened.** Deciding after an open would make
// "refused because it is sensitive" differ from "refused because it is missing",
// and that difference tells a caller whether a path exists. A path that is refused
// here has not been looked for.
func (r *Root) check(name string, write bool) (string, error) {
	rel := clean(name)
	if rel == "" || rel == "." {
		return "", fail(CodeOutsideRoot, rel, errors.New("empty path"))
	}
	if strings.ContainsRune(name, 0) {
		return "", fail(CodeOutsideRoot, rel, errors.New("path contains a NUL"))
	}
	if len(name) > MaxPathLen {
		return "", fail(CodeTooLarge, rel, fmt.Errorf("path is %d bytes, above the %d ceiling", len(name), MaxPathLen))
	}
	if strings.HasPrefix(name, "/") {
		return "", fail(CodeOutsideRoot, rel, errors.New("absolute path"))
	}
	if blocked(rel, write) {
		return "", fail(CodeBlockedPath, rel, nil)
	}
	return rel, nil
}

// clean normalises a caller-supplied path for use as a root-relative one. `..` is
// left in place rather than resolved: os.Root decides whether it escapes, and
// resolving here would answer a question this package is not the authority on.
func clean(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Clean(name)
	name = strings.TrimPrefix(name, "./")
	if name == ".." || strings.HasPrefix(name, "../") {
		return name
	}
	return strings.TrimPrefix(name, "/")
}

func writeCode(err error) Code {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return CodeNotFound
	case errors.Is(err, syscallErrNameTooLong):
		// A single component over NAME_MAX. That is a length, so it is reported as
		// one: `unavailable` would send a caller looking at the daemon rather than at
		// the path it chose.
		return CodeTooLarge
	default:
		return CodeUnavailable
	}
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// openRegular opens a file for reading, refusing a symlink in the last component
// and refusing anything that is not a regular file — without ever blocking.
func openRegular(r *os.Root, rel string) (*os.File, error) {
	dir, base := splitPath(rel)
	parent, err := r.OpenFile(dir, os.O_RDONLY|flagO_DIRECTORY, 0)
	if err != nil {
		return nil, walkError(err, rel)
	}
	defer parent.Close()

	fd, err := openLastNoFollow(int(parent.Fd()), base, os.O_RDONLY)
	if err != nil {
		return nil, lastOpenError(err, rel)
	}
	f := os.NewFile(uintptr(fd), rel)
	if f == nil {
		syscallClose(fd)
		return nil, fail(CodeUnavailable, rel, fmt.Errorf("cannot wrap the descriptor"))
	}
	// The type check, on the descriptor rather than the path, so it describes the
	// file that was actually opened.
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fail(CodeUnavailable, rel, err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fail(CodeNotRegular, rel, fmt.Errorf("not a regular file"))
	}
	return f, nil
}

// splitPath separates a cleaned relative path into the directory to open and the
// one component left to openat.
func splitPath(rel string) (dir, base string) {
	dir, base = path.Split(rel)
	if dir == "" {
		dir = "."
	}
	return strings.TrimSuffix(dir, "/"), base
}

// walkError maps a failure from resolving the path *through* os.Root. An escape
// arrives here as a permission error, which is os.Root's way of reporting it.
func walkError(err error, rel string) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fail(CodeNotFound, rel, nil)
	case errors.Is(err, os.ErrPermission):
		return fail(CodeOutsideRoot, rel, nil)
	default:
		return fail(CodeOutsideRoot, rel, err)
	}
}

// lastOpenError maps a failure from the final openat. No escape can appear here:
// the parent descriptor was already confined to the root by os.Root, so these are
// all ordinary, local conditions.
func lastOpenError(err error, rel string) error {
	switch {
	case errors.Is(err, syscallErrNotExist):
		return fail(CodeNotFound, rel, nil)
	case errors.Is(err, syscallErrSymlink):
		return fail(CodeSymlink, rel, nil)
	case errors.Is(err, syscallErrNotDir):
		return fail(CodeNotRegular, rel, nil)
	case errors.Is(err, syscallErrPerm), errors.Is(err, syscallErrAccess):
		return fail(CodeDenied, rel, nil)
	default:
		return fail(CodeUnavailable, rel, err)
	}
}
