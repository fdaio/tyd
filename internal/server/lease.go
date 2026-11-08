package server

import (
	"fmt"
	"time"

	"tyd/internal/audit"
)

// MaxLease bounds one approval lease. A lease is a reusable approval, and an
// unbounded one would be a different mode with a different name.
const MaxLease = time.Hour

type lease struct {
	expires time.Time
	ops     map[string]bool
}

// leaseOps are the requests a lease covers. Create, close, and file operations
// are deliberately absent: they stay single-request decisions.
var leaseOps = map[string]bool{
	opAttach: true,
	opWatch:  true,
	opRead:   true,
	opSend:   true,
}

func leaseKey(sessionID, principal string) string {
	return sessionID + "|" + principal
}

// grantLease records a reusable approval for one session and principal.
func (s *Server) grantLease(sessionID, principal string, d time.Duration) {
	if sessionID == "" || principal == "" || d <= 0 {
		return
	}
	if d > MaxLease {
		d = MaxLease
	}
	s.mu.Lock()
	if s.leases == nil {
		s.leases = make(map[string]lease)
	}
	s.leases[leaseKey(sessionID, principal)] = lease{
		expires: time.Now().Add(d),
		ops:     leaseOps,
	}
	s.mu.Unlock()
	s.audit(audit.Event{
		Kind:      audit.KindLeaseGrant,
		SessionID: sessionID,
		Principal: principal,
		Reason:    fmt.Sprintf("lease %s", d),
	})
}

// hasLease reports whether this exact principal may perform op now. An expired
// lease is removed and audited once.
func (s *Server) hasLease(sessionID, principal, op string) bool {
	now := time.Now()
	var expired *lease
	s.mu.Lock()
	l, ok := s.leases[leaseKey(sessionID, principal)]
	if ok && now.After(l.expires) {
		delete(s.leases, leaseKey(sessionID, principal))
		expired = &l
		ok = false
	}
	s.mu.Unlock()
	if expired != nil {
		s.audit(audit.Event{
			Kind:      audit.KindLeaseExpire,
			SessionID: sessionID,
			Principal: principal,
			Reason:    "lease expired",
		})
	}
	return ok && l.ops[op]
}

// pendingPrincipal finds the requester a digest names, before decideOnePending
// deletes the record. Empty digest means "the only waiting request"; the
// dispatch path has already refused the ambiguous case.
func (s *Server) pendingPrincipal(sessionID, digest string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, req := range s.pending {
		if req.sessionID != sessionID {
			continue
		}
		if digest != "" && req.digest != digest {
			continue
		}
		return req.principal
	}
	return ""
}
