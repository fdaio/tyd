package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Chained records.
//
// The audit log is a plain append-only file in the daemon user's own home, so
// the processes it is meant to record -- anything running inside a session on
// that machine -- can delete it, edit it, or replace it. A hash chain does not
// change who has write access. What it does is make an edit detectable: each
// record carries the hash of the one before it, so a line changed or removed in
// the middle leaves a break where the next line no longer follows.
//
// The limit is worth stating plainly, because it is the whole reason this is a
// speed bump and not a boundary: deleting the entire file and starting a fresh
// chain produces a file that verifies perfectly. Detecting that needs a copy the
// daemon user cannot reach. The real answer to "I do not trust the code in my
// session" is to run the session somewhere else; see docs/security.md.

// Chain returns the hash a record with this content and predecessor must carry.
// Field order does not matter: the event is marshalled canonically by json, and
// the hash is taken over those bytes, so a reader re-derives it from the same
// struct.
func chain(prev string, e Event) (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// chainStart is the predecessor of the first record.
const chainStart = "genesis"

// VerifyResult reports what a chain check found.
type VerifyResult struct {
	Records int
	// BrokenAt is the 1-based line number where the chain stops following. Zero
	// when the whole chain is intact.
	BrokenAt int
	Reason   string
}

func (v VerifyResult) OK() bool { return v.BrokenAt == 0 }

// Verify walks an audit log and checks that every record follows the one before
// it. It stops at the first break and says which line and why, because "the log
// is untrustworthy" is only useful if you can point at where it stopped making
// sense.
func Verify(path string) (VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return VerifyResult{}, err
	}
	defer func() { _ = f.Close() }()

	res := VerifyResult{}
	prev := chainStart
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var rec chainRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			// A line from before chaining existed is a bare event. Saying "not
			// readable" would be true and useless; saying "written by an older
			// tyd" is what the reader needs to know.
			var bare Event
			if json.Unmarshal(raw, &bare) == nil {
				res.BrokenAt = line
				res.Reason = "record has no chain fields (written by an older tyd?)"
				return res, nil
			}
			res.BrokenAt, res.Reason = line, "record is not readable"
			return res, nil
		}
		if rec.Hash == "" && rec.Prev == "" {
			// Chained envelope, but nothing in it: an unchained writer.
			res.BrokenAt = line
			res.Reason = "record has no chain fields (written by an older tyd?)"
			return res, nil
		}
		if rec.Prev != prev {
			res.BrokenAt = line
			res.Reason = fmt.Sprintf("record does not follow the previous one (prev %s, expected %s)",
				short(rec.Prev), short(prev))
			return res, nil
		}
		want, err := chain(rec.Prev, rec.Event)
		if err != nil {
			res.BrokenAt, res.Reason = line, "record could not be hashed"
			return res, nil
		}
		if want != rec.Hash {
			res.BrokenAt = line
			res.Reason = "record contents do not match its hash"
			return res, nil
		}
		prev = rec.Hash
		res.Records = line
	}
	if err := sc.Err(); err != nil {
		return res, err
	}
	if res.Records == 0 {
		res.Reason = "log is empty"
	}
	return res, nil
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "..."
}

// chainRecord is one line of the log: the event plus the two chain fields. It
// is a distinct type so the fields are named on the wire and the event keeps its
// own shape.
type chainRecord struct {
	Event Event  `json:"event"`
	Prev  string `json:"prev"`
	Hash  string `json:"hash"`
}

// encode renders a record for the log.
func (r chainRecord) encode() ([]byte, error) {
	return json.Marshal(r)
}

// lastHash reads the hash of the final record so a new one can follow it. An
// unreadable or unchained log starts a new chain rather than refusing to write,
// because losing audit records is worse than starting a fresh chain -- and a
// fresh chain is exactly what Verify will flag.
func lastHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return chainStart, nil
		}
		return "", err
	}
	defer func() { _ = f.Close() }()

	last := chainStart
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var rec chainRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			continue
		}
		if rec.Hash != "" {
			last = rec.Hash
		}
	}
	if err := sc.Err(); err != nil {
		return last, err
	}
	return last, nil
}
