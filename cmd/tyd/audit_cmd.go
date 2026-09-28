package main

import (
	"fmt"
	"os"

	"tyd/internal/audit"
	"tyd/internal/paths"
)

// runAuditVerify checks that an audit log's records form an unbroken chain.
//
// The daemon, its sessions and its log all belong to one user, so anything
// running in a session can edit or delete the file. The chain makes an edit in
// the middle detectable; deleting the whole file and starting again is not, and
// this says so rather than implying a guarantee it cannot keep. See
// docs/security.md.
func runAuditVerify(opts options) error {
	path := opts.auditLog
	if path == "" {
		path = paths.DefaultAudit()
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no audit log at %s (run with --audit-log PATH, or start tyd up with --audit-log)", path)
		}
		return err
	}

	res, err := audit.Verify(path)
	if err != nil {
		return err
	}
	if res.OK() {
		if res.Records == 0 {
			fmt.Printf("audit log %s: empty, nothing to check\n", path)
			return nil
		}
		fmt.Printf("audit log %s: %d record(s), chain intact\n", path, res.Records)
		fmt.Println("note: this detects an edit inside the log. A log deleted and rebuilt cannot be")
		fmt.Println("      detected from the log alone -- see docs/security.md")
		return nil
	}

	fmt.Printf("audit log %s: CHAIN BROKEN at line %d\n", path, res.BrokenAt)
	fmt.Printf("  %s\n", res.Reason)
	fmt.Printf("  %d record(s) checked before the break\n", res.Records)
	return fmt.Errorf("audit log chain broken at line %d: %s", res.BrokenAt, res.Reason)
}
