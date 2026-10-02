package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"tyd/internal/controlpanel"
	"tyd/internal/live"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

func startTestCP(t *testing.T) (string, interface{ Close() error }, error) {
	t.Helper()
	svc := controlpanel.New()
	addr, srv, err := controlpanel.ListenAndServe("127.0.0.1:0", svc)
	if err != nil {
		return "", nil, err
	}
	return addr.String(), srv, nil
}

// TestMain lets this test binary act as a live-agent.
//
// A session's shell lives in its own process, because that is what lets it
// outlive the client that opened it and still be read afterwards. The remote
// tests need a real shell on a real PTY, so they start one by re-executing this
// binary with the variables below, exactly as a daemon starts one by
// re-executing tyd. The fixture is then production's own shape, with a different
// binary playing the part.
func TestMain(m *testing.M) {
	if os.Getenv("TYD_TEST_LIVE_AGENT") == "1" {
		dir := os.Getenv("TYD_TEST_LIVE_DIR")
		// Empty unless a test asks for a ceiling, so these harnesses keep meaning
		// "no file root" rather than silently gaining one.
		if err := live.Run(dir, live.Config{FileRoot: os.Getenv("TYD_TEST_LIVE_FILE_ROOT")}); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
