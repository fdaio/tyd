package auth

type Cap string

const (
	CapList   Cap = "list"
	CapCreate Cap = "create"
	CapAttach Cap = "attach"
	CapWrite  Cap = "write"
	CapResize Cap = "resize"
	CapSignal Cap = "signal"
	CapClose  Cap = "close"
	// CapFile is "may attempt a file operation on a session's root". It is one
	// capability rather than a read and a write pair, because it is a coarse gate
	// and the fine one already exists: the root ceiling on the agent decides what a
	// file operation can actually reach, and with no ceiling configured the operations
	// do not exist at all. A second capability here would be a second thing to get
	// right without a second decision it controls.
	CapFile Cap = "file"
)

var OwnerCaps = []Cap{CapAttach, CapWrite, CapResize, CapSignal, CapClose, CapFile}

var AllGlobal = []Cap{CapList, CapCreate}
