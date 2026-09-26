package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"tyd/internal/controlpanel"
)

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
