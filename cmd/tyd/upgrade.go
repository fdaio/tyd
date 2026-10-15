package main

import (
	"fmt"
	"os"

	"tyd/internal/version"
)

// runVersion prints the build version.
func runVersion(opts options) error {
	fmt.Printf("tyd %s\n", version.Version)
	return nil
}

// runUpgrade downloads and installs the latest release.
//
// Flow: check for update → download tarball → verify SHA-256
// (fail closed) → atomically swap the binary → tell the user to
// restart the daemon. The daemon itself is not restarted: a running
// daemon keeps serving on the old binary until the user runs
// `tyd up` again, which is the safe default.
func runUpgrade(opts options) error {
	current := version.Version
	fmt.Printf("current: tyd %s\n", current)

	info := version.CheckForUpdate()
	if info == nil {
		// Either up to date, check failed, or dev build. Distinguish
		// "up to date" from "couldn't check" when we can.
		fmt.Println("already up to date (or no newer release found)")
		return nil
	}
	fmt.Printf("latest:  %s\n", info.Tag)
	fmt.Printf("downloading %s\n", info.URL)

	tag, err := version.Upgrade(info)
	if err != nil {
		return fmt.Errorf("upgrade: %w", err)
	}
	fmt.Printf("upgraded to %s\n", tag)
	fmt.Println("restart the daemon with `tyd up` to run the new version")
	return nil
}

// checkForUpdateNotice prints a one-line notice if a newer release
// exists. Called after successful commands; never blocks or fails.
// Skipped for version/upgrade themselves, non-terminals, and CI.
func checkForUpdateNotice() {
	if os.Getenv("CI") != "" {
		return
	}
	// Only notify on interactive terminals; agents parse stdout.
	if st, err := os.Stdout.Stat(); err != nil || (st.Mode()&os.ModeCharDevice) == 0 {
		return
	}
	info := version.CheckForUpdate()
	if info == nil {
		return
	}
	fmt.Fprintf(os.Stderr,
		"\nA new release of tyd is available: %s → %s\nRun `tyd upgrade` to update.\n",
		version.Version, info.Tag,
	)
}

// shouldCheckForUpdate reports whether the update notice applies to
// this command. version and upgrade handle their own output.
func shouldCheckForUpdate(cmd string) bool {
	return cmd != "version" && cmd != "upgrade"
}
