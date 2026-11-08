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
)

var OwnerCaps = []Cap{CapAttach, CapWrite, CapResize, CapSignal, CapClose}

var AllGlobal = []Cap{CapList, CapCreate}
