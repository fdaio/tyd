package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSessionListJSONShape(t *testing.T) {
	var b bytes.Buffer
	rows := []sessionListRow{
		{ID: "abc", Alias: "build", Peer: "laptop", State: "DETACHED", Created: "2026-01-02 03:04"},
	}
	if err := writeSessionListJSON(&b, rows, 2); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Sessions []sessionListRow `json:"sessions"`
		Hidden   int              `json:"hidden"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("invalid json %q: %v", b.String(), err)
	}
	if len(got.Sessions) != 1 || got.Sessions[0].ID != "abc" || got.Sessions[0].State != "DETACHED" {
		t.Fatalf("sessions = %+v", got.Sessions)
	}
	if got.Hidden != 2 {
		t.Errorf("hidden = %d, want 2", got.Hidden)
	}
}

func TestCreatedJSONShape(t *testing.T) {
	var b bytes.Buffer
	writeCreatedJSON(&b, "abc", "DETACHED", "laptop")
	var got struct {
		ID    string `json:"id"`
		State string `json:"state"`
		Peer  string `json:"peer"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("invalid json %q: %v", b.String(), err)
	}
	if got.ID != "abc" || got.State != "DETACHED" || got.Peer != "laptop" {
		t.Fatalf("got %+v", got)
	}
}
