package auth

type Cap string

const (
	CapList   Cap = "list"
	CapCreate Cap = "create"
	CapAttach Cap = "attach"
	CapWatch  Cap = "watch"
	CapRead   Cap = "read"
	CapWrite  Cap = "write"
	CapResize Cap = "resize"
	CapSignal Cap = "signal"
	CapClose  Cap = "close"

	// The "any session" caps are local policy, not wire capabilities. A viewer
	// holds them and can watch or read every session; it does not hold
	// CapAttach, so it cannot take the interactive writer slot.
	CapWatchAny Cap = "watch_any"
	CapReadAny  Cap = "read_any"
)

var OwnerCaps = []Cap{CapAttach, CapWatch, CapRead, CapWrite, CapResize, CapSignal, CapClose}

var AllGlobal = []Cap{CapList, CapCreate}
