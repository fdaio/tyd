package epcache

import (
	"path/filepath"
	"testing"
	"time"

	"tyd/internal/controlpanel"
)

func TestGetPutInvalidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoints.json")
	if _, ok := Get(path, "p1"); ok {
		t.Fatal("empty cache hit")
	}
	ep := &controlpanel.EndpointResponse{
		Addr:      "10.0.0.1:1",
		CertFP:    "abc",
		Transport: "tls",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := Put(path, "p1", ep); err != nil {
		t.Fatal(err)
	}
	got, ok := Get(path, "p1")
	if !ok || got.Addr != "10.0.0.1:1" || got.CertFP != "abc" {
		t.Fatalf("%v %v", ok, got)
	}
	if err := Invalidate(path, "p1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := Get(path, "p1"); ok {
		t.Fatal("still cached after invalidate")
	}
}

func TestExpiredMiss(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoints.json")
	if err := Put(path, "p1", &controlpanel.EndpointResponse{
		Addr:      "10.0.0.1:1",
		CertFP:    "abc",
		ExpiresAt: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := Get(path, "p1"); ok {
		t.Fatal("expired should miss")
	}
}
