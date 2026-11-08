package main

import (
	"context"
	"fmt"

	"tyd/internal/sandbox"
)

// buildSandboxSpec resolves the operator's sandbox flags into one policy. It
// does not start a container or touch the runtime; that is Check's job.
func buildSandboxSpec(opts options) (sandbox.Spec, error) {
	backend, err := sandbox.Resolve(opts.sandboxBackend)
	if err != nil {
		return sandbox.Spec{}, err
	}
	s := sandbox.Spec{
		Backend: backend,
		Image:   opts.sandboxImage,
		Workdir: opts.sandboxWorkdir,
		Shell:   opts.sandboxShell,
		Network: opts.sandboxNetwork,
		Memory:  opts.sandboxMemory,
		CPUs:    opts.sandboxCPUs,
		Pids:    opts.sandboxPids,
	}
	s, err = s.Normalize()
	if err != nil {
		return sandbox.Spec{}, err
	}
	return s, nil
}

// checkSandbox makes the daemon fail at startup, not on the first session,
// when the runtime is missing or the image is not local.
func checkSandbox(ctx context.Context, s sandbox.Spec) error {
	if err := s.Check(ctx); err != nil {
		return fmt.Errorf("sandbox: %w", err)
	}
	return nil
}
