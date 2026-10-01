package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tyd/internal/client"
	"tyd/internal/live"
	"tyd/internal/strutil"
)

// exitSessionInUse is returned when a send is refused because someone holds
// the attach slot. It is distinct so a script can tell "busy" from "broken".
const exitSessionInUse = 3

// splitFlags moves flags ahead of positional arguments. Go's flag package
// stops at the first non-flag word, but the documented order here is
// "read <session> --cursor N", so the flags have to be lifted out first.
func splitFlags(fs *flag.FlagSet, args []string) (flagArgs, positional []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			return flagArgs, positional, nil
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			flagArgs = append(flagArgs, a)
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			return nil, nil, fmt.Errorf("unknown flag %s", a)
		}
		flagArgs = append(flagArgs, a)
		// A non-boolean flag takes the next word as its value.
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 >= len(args) {
			return nil, nil, fmt.Errorf("%s requires a value", a)
		}
		i++
		flagArgs = append(flagArgs, args[i])
	}
	return flagArgs, positional, nil
}

func runSessionSend(opts options) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stdin := fs.Bool("stdin", false, "read raw bytes from stdin")
	asJSON := fs.Bool("json", false, "print the resulting cursor and epoch")
	flagArgs, pos, err := splitFlags(fs, opts.rest[1:])
	if err != nil {
		return fmt.Errorf("usage: tyd session send <session_id|alias> [DATA] [--stdin]: %w", err)
	}
	if err := fs.Parse(flagArgs); err != nil {
		return fmt.Errorf("usage: tyd session send <session_id|alias> [DATA] [--stdin]: %w", err)
	}
	rest := pos
	if len(rest) == 0 {
		return fmt.Errorf("usage: tyd session send <session_id|alias> [DATA] [--stdin]")
	}
	sid, err := resolveSessionRef(opts, rest[0])
	if err != nil {
		return err
	}

	var data []byte
	switch {
	case *stdin:
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	case len(rest) > 1:
		data, err = strutil.ParseSendData(strings.Join(rest[1:], " "))
		if err != nil {
			return fmt.Errorf("bad data: %w", err)
		}
	default:
		return fmt.Errorf("send needs DATA or --stdin")
	}
	if len(data) == 0 {
		return fmt.Errorf("send needs at least one byte")
	}

	ep, peerID, fromCatalog, err := endpointForSession(opts, sid)
	if err != nil {
		return err
	}
	if err := ensureLocalDaemon(opts, ep); err != nil {
		return err
	}
	key, err := loadIdentity(opts.identity)
	if err != nil {
		return err
	}
	rememberPeerSession(opts, peerID, sid)
	_ = fromCatalog
	rep, err := client.Send(ep, key, sid, data)
	if err != nil {
		if strings.Contains(err.Error(), "session in use") {
			fmt.Fprintf(os.Stderr, "tyd: %s\n", err)
			os.Exit(exitSessionInUse)
		}
		return err
	}
	touchSession(opts, sid)
	markUsed(opts, peerID, sid)
	if *asJSON {
		rec := sendRecord{SessionID: sid, Written: rep.Written, Cursor: rep.Cursor, Epoch: rep.Epoch}
		line, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "%s\n", line)
	}
	return nil
}

// sendRecord is the --json output of a send. Cursor is the output position from
// before the write, so the caller can read only what its keys produced.
type sendRecord struct {
	SessionID string `json:"session_id"`
	Written   int    `json:"written"`
	Cursor    uint64 `json:"cursor"`
	Epoch     uint64 `json:"epoch"`
}

// readPage is one --json record.
type readPage struct {
	Type        string `json:"type"`
	SessionID   string `json:"session_id"`
	Data        string `json:"data"`
	Cursor      uint64 `json:"cursor"`
	CursorNext  uint64 `json:"cursor_next"`
	Epoch       uint64 `json:"epoch"`
	AtEnd       bool   `json:"at_end"`
	Dropped     uint64 `json:"dropped"`
	CursorAhead bool   `json:"cursor_ahead"`
	Exited      bool   `json:"exited"`
	Reason      string `json:"reason"`
}

func runSessionRead(opts options) error {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cursor := fs.Uint64("cursor", 0, "resume from this byte offset")
	epoch := fs.Uint64("epoch", 0, "generation from the last page")
	wait := fs.Duration("wait", 0, "wait up to this long for new output")
	asJSON := fs.Bool("json", false, "one JSON object per page")
	follow := fs.Bool("follow", false, "keep pulling until the shell exits")
	untilIdle := fs.Duration("until-idle", 0, "return once output has been quiet this long")
	untilMatch := fs.String("until-match", "", "return once the cleaned output matches this RE2 pattern")
	maxBytes := fs.Int("max-bytes", 0, "return once this many bytes have accumulated")
	flagArgs, pos, err := splitFlags(fs, opts.rest[1:])
	if err != nil {
		return fmt.Errorf("usage: tyd session read <session_id|alias> [--cursor N] [--epoch E] [--wait D] [--json] [--follow]: %w", err)
	}
	if err := fs.Parse(flagArgs); err != nil {
		return fmt.Errorf("usage: tyd session read <session_id|alias> [--cursor N] [--epoch E] [--wait D] [--json] [--follow]: %w", err)
	}
	rest := pos
	if len(rest) == 0 {
		return fmt.Errorf("usage: tyd session read <session_id|alias> [--cursor N] [--epoch E] [--wait D] [--json] [--follow]")
	}
	sid, err := resolveSessionRef(opts, rest[0])
	if err != nil {
		return err
	}
	cond := live.ReadConditions{IdleMS: uint32(*untilIdle / time.Millisecond), Match: *untilMatch, MaxBytes: uint32(*maxBytes)}
	if *follow && *wait == 0 {
		*wait = 2 * time.Second
	}
	if *wait < 0 {
		return fmt.Errorf("--wait must not be negative")
	}
	// A condition with no wait would return at once, which is the opposite of
	// what the caller asked for. The server refuses it too; catching it here
	// gives a better message.
	if *wait == 0 && (cond.IdleMS > 0 || cond.Match != "" || cond.MaxBytes > 0) {
		return fmt.Errorf("--until-idle, --until-match and --max-bytes need --wait")
	}
	if *untilIdle < 0 {
		return fmt.Errorf("--until-idle must not be negative")
	}

	ep, peerID, fromCatalog, err := endpointForSession(opts, sid)
	if err != nil {
		return err
	}
	if err := ensureLocalDaemon(opts, ep); err != nil {
		return err
	}
	key, err := loadIdentity(opts.identity)
	if err != nil {
		return err
	}
	rememberPeerSession(opts, peerID, sid)

	// Ctrl-C ends a follow without turning it into a failure.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	out := os.Stdout
	cur, epNo := *cursor, *epoch
	used := false
	for {
		if *follow {
			select {
			case <-sig:
				return nil
			default:
			}
		}
		page, err := client.Read(ep, key, sid, cur, epNo, *wait, cond)
		if err != nil {
			// A connection error is a failure, not a reason to reconnect.
			return err
		}
		// A follow reads for as long as the caller lets it, so the clock is
		// stamped on the first page rather than on every one.
		if !used {
			used = true
			touchSession(opts, sid)
			markUsed(opts, peerID, sid)
		}
		if page.Dropped > 0 {
			fmt.Fprintf(os.Stderr, "tyd: %d bytes before this cursor are gone; resuming at %d\n",
				page.Dropped, page.CursorNext)
		}
		if page.CursorAhead {
			fmt.Fprintf(os.Stderr, "tyd: cursor was past the durable output; resuming at %d (epoch %d)\n",
				page.CursorNext, page.Epoch)
		}
		cur, epNo = page.CursorNext, page.Epoch

		if *asJSON {
			rec := readPage{
				Type:        "read_result",
				SessionID:   sid,
				Data:        base64.StdEncoding.EncodeToString(page.Data),
				Cursor:      cur - uint64(len(page.Data)) - page.Dropped,
				CursorNext:  page.CursorNext,
				Epoch:       page.Epoch,
				AtEnd:       page.AtEnd,
				Dropped:     page.Dropped,
				CursorAhead: page.CursorAhead,
				Exited:      page.Exited,
				Reason:      page.Reason,
			}
			line, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(out, "%s\n", line); err != nil {
				return err
			}
		} else if len(page.Data) > 0 {
			if _, err := out.Write(page.Data); err != nil {
				return err
			}
		}
		if !*asJSON {
			fmt.Fprintf(os.Stderr, "tyd: cursor %d epoch %d at_end=%v exited=%v reason=%s\n",
				page.CursorNext, page.Epoch, page.AtEnd, page.Exited, page.Reason)
		}
		if page.Exited {
			return nil
		}
		if !*follow {
			return nil
		}
		_ = fromCatalog
	}
}
