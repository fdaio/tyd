//go:build unix

package fileroot

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	flagO_DIRECTORY = syscall.O_DIRECTORY
	flagO_CLOEXEC   = syscall.O_CLOEXEC
)

// Named once so the error mapping in root.go reads as a list of conditions rather
// than a list of syscall numbers. A symlink refused by O_NOFOLLOW arrives as ELOOP.
var (
	syscallErrNotExist    = syscall.ENOENT
	syscallErrSymlink     = syscall.ELOOP
	syscallErrNotDir      = syscall.ENOTDIR
	syscallErrPerm        = syscall.EPERM
	syscallErrAccess      = syscall.EACCES
	syscallErrNameTooLong = syscall.ENAMETOOLONG
)

// openLastNoFollow opens base within an already-open directory, refusing to follow
// a symlink in that last component.
//
// This exists because **os.Root does not do it.** os.Root always passes O_NOFOLLOW
// down, and when the kernel refuses, doInRoot treats the resulting errSymlink as
// "this element is a symlink which should be followed" and resolves it itself. The
// consequence is that os.Root.OpenFile("link") opens what link points at, silently,
// and a caller's own O_NOFOLLOW has no effect on it.
//
// So the walk stays with os.Root and only the final step is taken here. Opening the
// parent through os.Root keeps every intermediate component confined to the root,
// and taking the last step with openat against that descriptor is what makes the
// symlink refusal real — the kernel decides, as part of the open, with no window
// between a check and a use.
//
// O_NONBLOCK is here for the same reason and matters just as much: without it,
// opening a FIFO for reading waits for a writer that may never come, and the
// "not a regular file" check below is never reached because the open has not
// returned.
func openLastNoFollow(parentFD int, base string, flags int) (int, error) {
	return unix.Openat(parentFD, base, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|flagO_CLOEXEC, 0)
}

func syscallClose(fd int) error { return syscall.Close(fd) }

// ownerOf is the file's uid and gid, so a write can put them back. A file written as
// one user and read as another should not silently change hands.
func ownerOf(info os.FileInfo) (uid, gid int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}
