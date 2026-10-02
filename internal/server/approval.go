package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"tyd/internal/auth"
)

// An approval is one-shot and expires, but until now it was bound to *a session
// from a principal* rather than to *a request*. Inside the approval window whoever
// called first spent it, and the thing that then executed was not necessarily the
// thing the operator was shown:
//
//	tyd approval needed: alice wants session abc123 (tyd session approve abc123)
//
// That survives while every gated request is a read or a keystroke against a
// session the operator already named. It stops surviving the moment a gated
// request means "write this file", where an approval granted for a read could be
// spent on a write somewhere else entirely.
//
// So an approval carries a digest of the request it approves, and is spent only on
// a match.

// approvalDigest is what an approval is bound to.
//
// **It binds exactly what the operator can see, and nothing else.** Operation,
// session, byte count, mode. A hash the caller claims about content it did not
// write — `expected_sha256` — is deliberately absent: on a low-entropy file a bare
// hash is an offline dictionary verifier, and this digest lives in a record the
// operator reads and in a line on stderr.
//
// Computed here rather than taken from the peer. A peer that chose its own digest
// could bind an approval for one request to a different one, which is the defect
// being fixed.
func approvalDigest(op, sessionID string, size int64) string {
	h := sha256.New()
	// NUL separated so no combination of fields can be read as another one.
	for _, part := range []string{op, sessionID, strconv.FormatInt(size, 10)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// shortDigest is what an operator is shown. Enough to tell two pending requests
// apart, not enough to be worth attacking.
func shortDigest(d string) string {
	if len(d) <= 12 {
		return d
	}
	return d[:12]
}

// approval is a spent-or-spendable decision. The digest is kept so a mismatch can
// be told apart from a missing approval: one is "you approved something else" and
// the other is "nothing was approved".
type approval struct {
	expires time.Time
	digest  string
}

// pendingCap bounds how many distinct requests one session can have waiting, so a
// peer cannot bury an operator in a list. Requests that share a digest share a
// pending record, so a retry loop does not consume the budget.
const pendingCap = 16

// describeRequest is the operator-facing summary of what is being approved. It
// carries no content: a `send` shows its size and nothing more, which is the same
// rule #122 follows for a password.
func describeRequest(op, sessionID string, size int64) string {
	switch op {
	case opSend:
		return fmt.Sprintf("send %d bytes to %s", size, sessionID)
	case opRead:
		return "read " + sessionID
	default:
		return op + " " + sessionID
	}
}

// Operation names, kept in one place so the digest and the operator's text cannot
// drift apart.
const (
	opCreate = "create"
	opAttach = "attach"
	opWatch  = "watch"
	opRead   = "read"
	opSend   = "send"
)

// approvalKey is the map key for both the pending record and the spent decision.
// Including the digest is what makes an approval specific, and it makes two
// identical requests share one record for free.
func approvalKey(sessionID string, pub string, digest string) string {
	return sessionID + "|" + pub + "|" + digest
}

// splitApprovalKey recovers the session id from a key, which is what forgetSession
// and the listing need.
func splitApprovalKey(key string) (sessionID, pub, digest string) {
	parts := strings.SplitN(key, "|", 3)
	if len(parts) != 3 {
		return key, "", ""
	}
	return parts[0], parts[1], parts[2]
}

// gatePub is the principal half of a gate key, or empty for an unauthenticated
// connection. Kept here so the key is built in one place.
func gatePub(p *auth.Principal) string {
	if p == nil {
		return ""
	}
	return auth.EncodePublic(p.Pub)
}

// countPendingLocked is how many distinct requests one principal has waiting on a
// session. Callers hold s.mu.
//
// Counted on the key prefix rather than on the record's fields: the record carries
// the principal's *name*, which is for the operator to read, while the key carries
// the encoded public key. Comparing one against the other counts nothing, and a cap
// that never fires looks exactly like a cap that is not there.
func (s *Server) countPendingLocked(sessionID string, p *auth.Principal) int {
	prefix := sessionID + "|" + gatePub(p) + "|"
	now := time.Now()
	n := 0
	for key, req := range s.pending {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		// Expired entries do not count, and are swept here rather than only where
		// they are read.
		//
		// Expiry used to happen in one place: the listing. In production that
		// listing runs when somebody invokes `tyd session approve`, so a principal
		// that filled its slots and was never approved kept them — the cap counted
		// them, every later request was refused, and nothing would ever clear them
		// short of the operator running a command that had itself stopped working.
		// A limit that can be reached permanently, by the party it is meant to slow
		// down, is a denial of service with a 10-minute fuse that never burns down.
		if now.Sub(req.at) > s.cfg.ApprovalTTL {
			delete(s.pending, key)
			continue
		}
		n++
	}
	return n
}

// pendingFor lists what is waiting on a session, oldest first, for an operator who
// has to choose between them.
func (s *Server) pendingFor(sessionID string) []PendingApproval {
	all := s.PendingApprovals()
	out := make([]PendingApproval, 0, len(all))
	for _, p := range all {
		if p.SessionID == sessionID {
			out = append(out, p)
		}
	}
	return out
}

// ambiguousApproval refuses, and says what is waiting.
//
// Silently approving the first would be the defect this whole change exists to
// remove: an operator who was shown "send 9 bytes" would end up having also
// approved a read. So the caller is told what is pending and how to name the one
// they meant.
func ambiguousApproval(sessionID string, waiting []PendingApproval) error {
	var b strings.Builder
	fmt.Fprintf(&b, "session %s has %d requests waiting for approval, so approving all of them "+
		"would decide requests you were not shown. Name the one you mean:", sessionID, len(waiting))
	for _, w := range waiting {
		fmt.Fprintf(&b, "\n  %s  %s  (%s)", shortDigest(w.Digest), w.Request, w.Principal)
	}
	fmt.Fprintf(&b, "\n  tyd session approve %s --digest <hex>", sessionID)
	return fmt.Errorf("%s", b.String())
}

// checkApproverVersion refuses an approving client that does not say what it is.
//
// Same reasoning as the rest of #124, and the cost of getting it wrong is higher:
// falling back to the old behaviour would leave an unbound approval working for
// exactly the peers that have not upgraded, which are the ones least likely to
// notice anything is wrong.
func (s *Server) checkApproverVersion(v int) error {
	if v == 0 {
		return fmt.Errorf("approve: this client does not send a handshake version, so which "+
			"request it is approving is unknown. It speaks handshake version 0, this daemon "+
			"speaks %d: upgrade the client", auth.CurrentVersion)
	}
	if v < auth.MinHandshakeVersion || v > auth.CurrentVersion {
		return fmt.Errorf("approve: this client speaks handshake version %d, this daemon speaks "+
			"%d: upgrade the client", v, auth.CurrentVersion)
	}
	return nil
}

// approvedRecordForTest is the stored approval as text, so a test can search it for
// content it should not hold.
func (s *Server) approvedRecordForTest(sessionID, digest string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, a := range s.approved {
		if strings.HasPrefix(key, sessionID+"|") && a.digest == digest {
			return key + " " + a.digest
		}
	}
	return ""
}
