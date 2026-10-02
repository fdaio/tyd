package mcp

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// A fan-out asks several machines the same question at once. Three things have to
// hold, and each is easy to get wrong:
//
//   - The order does not depend on who answered first. Results are written by
//     index, so a list is the same list however the machines happened to reply.
//   - One machine is still probed one row at a time. The slot that keeps a pre-mode
//     approval from being spent twice is per target, so fifty sessions on one
//     machine are still fifty serial probes. The speedup is between machines, and
//     that boundary is real rather than a detail.
//   - A machine that fails does not fail the call. A model asking "what is running
//     everywhere" needs the other three answers far more than it needs to be told
//     the whole thing failed.

// fanoutWorkers bounds how many machines are probed at once. Small on purpose: the
// win is one slow machine no longer holding up the rest, not saturating a link.
const (
	fanoutWorkers    = 4
	fanoutMaxWorkers = 8
	// fanoutTotal caps the whole call, because a machine that accepts a connection
	// and then stops answering would otherwise hold wg.Wait open indefinitely. It
	// is a backstop; each probe carries its own shorter timeout.
	fanoutTotal = 20 * time.Second
	// fanoutPerTarget bounds one machine's probe, so a slow machine spends its own
	// budget rather than the call's.
	fanoutPerTarget = 8 * time.Second
)

// listMany is session_list across several targets.
//
// The single-target path is left exactly as it was, so a caller that does not ask
// for a fan-out gets the behaviour it had before this existed.
func (s *server) listMany(ctx context.Context, a args) (string, any, error) {
	listed, err := s.backend.List(ctx)
	if err != nil {
		return "", nil, mapError(err, Session{})
	}
	targets, err := s.listTargets(ctx, a)
	if err != nil {
		return "", nil, err
	}

	// Group by identity, not by label. A session's row carries the label the
	// catalog recorded, and two labels can name one machine — grouping by label
	// would probe that machine twice, which is two probes past the same approval
	// gate, the very thing the slot exists to prevent.
	identityOf := make(map[string]string, len(targets)) // label -> identity
	for _, t := range targets {
		identityOf[t.Label] = t.Identity
	}
	byIdentity := make(map[string][]Listed, len(targets))
	for _, it := range listed {
		id, known := identityOf[it.Session.Peer]
		if !known {
			// Recorded against a machine this process does not serve. The
			// single-target path lists it so a model can see it exists; a fan-out
			// that did not ask about that machine does not claim it.
			continue
		}
		byIdentity[id] = append(byIdentity[id], it)
	}

	type outcome struct {
		rows    []sessionRow
		failed  string
		skipped string
	}
	results := make([]outcome, len(targets))

	workers := fanoutWorkers
	if len(targets) < workers {
		workers = len(targets)
	}
	if workers > fanoutMaxWorkers {
		workers = fanoutMaxWorkers
	}
	if workers < 1 {
		workers = 1
	}

	totalCtx, cancelTotal := context.WithTimeout(ctx, fanoutTotal)
	defer cancelTotal()
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-totalCtx.Done():
				results[i] = outcome{skipped: skipNote(totalCtx.Err())}
				return
			}
			rows := byIdentity[targets[i].Identity]
			if len(rows) == 0 {
				// A machine with nothing in the catalog is not a failure, and
				// probing it would be a read past an approval gate for no answer.
				results[i] = outcome{}
				return
			}
			targetCtx, cancel := context.WithTimeout(totalCtx, fanoutPerTarget)
			defer cancel()
			probed := s.probeTarget(targetCtx, targets[i].Label, rows)
			results[i].rows = probed
			// A machine whose every probe failed is reported by name, not only as
			// rows that say so. The reader asked a question of three machines and
			// needs to know one of them did not answer, without reading every row to
			// work that out.
			if reason, all := worstProbeFailure(probed); all && reason != "" {
				results[i].failed = reason
			}
		}(i)
	}
	// Waits on every goroutine above, each of which honours the context it was
	// given. A probe that ignores its context is a transport bug, and the
	// per-target timeout is here to make that visible rather than to hang on it.
	wg.Wait()

	var b strings.Builder
	fmt.Fprintf(&b, "%d session(s) across %d target(s).\n", len(listed), len(targets))
	out := make([]sessionRow, 0, len(listed))
	var unreachable []string
	for i, t := range targets {
		res := results[i]
		if res.failed != "" {
			unreachable = append(unreachable, fmt.Sprintf("%s: %s", orLocal(t.Label), res.failed))
		}
		if res.skipped != "" {
			unreachable = append(unreachable, fmt.Sprintf("%s: %s", orLocal(t.Label), res.skipped))
		}
		for _, row := range res.rows {
			out = append(out, row)
			renderRow(&b, row)
		}
	}

	s.logf("session_list targets=%d rows=%d unreachable=%d", len(targets), len(out), len(unreachable))
	footer := "[tyd: rows are from the local catalog; each state is from a probe read"
	if len(unreachable) > 0 {
		footer += "; could not be reached: " + strings.Join(unreachable, ", ")
	}
	if gated := s.gatedTargets(); len(gated) > 0 {
		footer += "; no probe on " + strings.Join(gated, ", ") + ", which needs approval on the target"
	}
	return fence(b.String()) + "\n" + footer + "]",
		&result{Output: b.String(), Reason: "catalog", SessionState: "catalog", Sessions: out}, nil
}

// listTargets resolves the peers argument into an ordered, deduplicated target list.
//
// Absent means today's behaviour, not everything — a caller that did not ask for a
// fan-out should not suddenly get one. An empty list is a mistake rather than a
// request for nothing.
func (s *server) listTargets(ctx context.Context, a args) ([]Target, error) {
	// peer is not in this tool's schema because a list reports every target, so a
	// peer argument has nothing to select. Sent anyway, it is refused rather than
	// ignored: a model that sent it believes it chose a machine, and saying
	// nothing back leaves it believing that.
	if a.has("peer") {
		return nil, invalidParams("peer is not an argument of session_list: it reports every target " +
			"already. Use peers to choose which of them to probe")
	}
	names, err := a.stringList("peers")
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, invalidParams("peers must name at least one machine, or \"all\". " +
			"Omit it entirely for the single default target")
	}

	known, err := s.backend.Targets(ctx)
	if err != nil {
		return nil, mapError(err, Session{})
	}

	if len(names) == 1 && names[0] == "all" {
		if len(known) == 0 {
			return nil, nil
		}
		// Sorted, so "all" is the same list every time. Request order is a choice
		// the caller makes; this one is not.
		out := append([]Target(nil), known...)
		sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
		return dedupeTargets(out), nil
	}

	byLabel := make(map[string]Target, len(known))
	for _, t := range known {
		byLabel[t.Label] = t
	}
	out := make([]Target, 0, len(names))
	for _, n := range names {
		t, ok := byLabel[n]
		if !ok {
			return nil, invalidParams("peer %q is not served by this process. "+
				"Start the server with --allow-peer, or pass \"all\"", n)
		}
		out = append(out, t)
	}
	return dedupeTargets(out), nil
}

// dedupeTargets drops later entries whose identity has already been seen, keeping
// the caller's order for the ones that survive.
func dedupeTargets(in []Target) []Target {
	seen := make(map[string]bool, len(in))
	out := make([]Target, 0, len(in))
	for _, t := range in {
		if seen[t.Identity] {
			continue
		}
		seen[t.Identity] = true
		out = append(out, t)
	}
	return out
}

// skipNote explains a machine the fan-out never got to, which is a different
// problem from one that refused.
func skipNote(err error) string {
	if err == nil {
		return "not probed: the fan-out did not reach this machine"
	}
	return "not probed: the fan-out ran out of time before reaching this machine"
}

// worstProbeFailure reports why a machine could not be reached, and whether every
// probe on it failed. One row failing on a machine with fifty sessions is a fact
// about that session; all of them failing is a fact about the machine.
func worstProbeFailure(rows []sessionRow) (string, bool) {
	probed, failed := 0, 0
	reason := ""
	for _, r := range rows {
		if !r.Probed {
			continue
		}
		probed++
		if r.ProbeError == "" {
			continue
		}
		failed++
		if reason == "" {
			reason = r.ProbeError
		}
	}
	if probed == 0 || failed != probed {
		return "", false
	}
	return reason, true
}

// renderRow writes one row in the single-target format, so a fan-out row and a
// single-target row read the same.
func renderRow(b *strings.Builder, row sessionRow) {
	fmt.Fprintf(b, "- %s (%s) on %s: %s", row.Session, row.ID, row.Peer, row.State)
	if row.OpenedByUs {
		b.WriteString(", opened by this process")
	}
	if row.Recorded != "" && !strings.EqualFold(row.Recorded, row.State) {
		fmt.Fprintf(b, ", catalog says %s", row.Recorded)
	}
	switch {
	case row.ProbeError == "":
	case row.Probed:
		fmt.Fprintf(b, "\n  probe failed: %s", row.ProbeError)
	default:
		fmt.Fprintf(b, "\n  not probed: %s", row.ProbeError)
	}
	b.WriteString("\n")
}
