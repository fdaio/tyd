package live

import (
	"errors"
	"regexp"
	"time"
)

// Reason says why a read returned. Every reply carries one, so a caller can
// tell "your condition fired" from "the wait ran out".
const (
	ReasonAvailable  = "available"
	ReasonMatch      = "match"
	ReasonIdle       = "idle"
	ReasonMaxBytes   = "max_bytes"
	ReasonTimeout    = "timeout"
	ReasonExited     = "exited"
	ReasonCursorHead = "cursor_ahead"
)

const (
	// MinIdleMS keeps a caller from asking for a pause so short it is just
	// polling, and MaxIdleMS matches the server wait cap.
	MinIdleMS = 50
	MaxIdleMS = 30000
	// MaxMatchPattern bounds the pattern. RE2 is linear time, so a long
	// pattern cannot be a denial of service, but it can still be unreadable.
	MaxMatchPattern = 512
	// MaxConditionBytes caps max_bytes. One reply is already capped at
	// ReadMax, so anything larger would be clamped anyway.
	MaxConditionBytes = 64 << 10
	// matchEvalInterval rate-limits regex evaluation. A session producing
	// output faster than the reader consumes it would otherwise re-run the
	// match on every wake and burn the CPU doing it.
	matchEvalInterval = 20 * time.Millisecond
)

// ErrInvalidCondition is returned for a condition the server will not honour.
var ErrInvalidCondition = errors.New("invalid read condition")

// ReadConditions carries the raw request fields across the wire to the
// agent, which is where they are validated. The daemon copies them through
// without interpreting them, so an old agent simply ignores what it does not
// know and a new one refuses a condition it cannot honour.
type ReadConditions struct {
	IdleMS   uint32
	Match    string
	MaxBytes uint32
}

// Conditions are the optional wake-up rules for a read. A zero value means
// none were given, and the read behaves as it did before conditions existed.
type Conditions struct {
	Idle     time.Duration
	Match    *regexp.Regexp
	MaxBytes int
}

// Any reports whether the caller asked for anything.
func (c Conditions) Any() bool {
	return c.Idle > 0 || c.Match != nil || c.MaxBytes > 0
}

// Validate checks the ranges and compiles the pattern. An invalid condition
// is refused outright rather than silently ignored, because a caller waiting
// on a condition that never fires would sit there until the timeout.
func ValidateConditions(idleMS uint32, pattern string, maxBytes uint32) (Conditions, error) {
	var c Conditions
	if idleMS > 0 {
		if idleMS < MinIdleMS || idleMS > MaxIdleMS {
			return c, ErrInvalidCondition
		}
		c.Idle = time.Duration(idleMS) * time.Millisecond
	}
	if pattern != "" {
		if len(pattern) > MaxMatchPattern {
			return c, ErrInvalidCondition
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return c, ErrInvalidCondition
		}
		c.Match = re
	}
	if maxBytes > 0 {
		if maxBytes > MaxConditionBytes {
			return c, ErrInvalidCondition
		}
		c.MaxBytes = int(maxBytes)
	}
	return c, nil
}
