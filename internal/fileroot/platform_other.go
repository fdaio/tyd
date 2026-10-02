//go:build !unix

package fileroot

import (
	"errors"
	"fmt"
	"os"
)

const (
	flagO_DIRECTORY = 0
	flagO_CLOEXEC   = 0
)

// No syscall numbers to name here; the unix build carries the mapping.
var (
	syscallErrNotExist = errors.New("not exist")
	syscallErrSymlink  = errors.New("symlink")
	syscallErrNotDir   = errors.New("not a directory")
	syscallErrPerm     = errors.New("operation not permitted")
	syscallErrAccess   = errors.New("access denied")
)

// openLastNoFollow has no equivalent here. The unix build is the one that carries
// the symlink and FIFO guarantees, so this refuses rather than pretending: a caller
// on this platform gets an error, not a weaker promise that looks identical.
func openLastNoFollow(int, string, int) (int, error) {
	return -1, fmt.Errorf("fileroot: a no-follow open is not implemented on this platform")
}

// syscallClose is never reached on a platform without openat; openLastNoFollow has
// already failed by then.
func syscallClose(int) error { return errors.New("fileroot: no descriptor to close") }

// ownerOf has nothing to read on a platform without unix ownership.
func ownerOf(os.FileInfo) (uid, gid int) { return -1, -1 }
