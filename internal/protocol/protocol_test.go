package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	in := Frame{
		Type:      TypeWrite,
		SessionID: "abc",
		Data:      []byte("hello\n"),
		Rows:      24,
		Cols:      80,
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != in.Type || out.SessionID != in.SessionID || string(out.Data) != string(in.Data) {
		t.Fatalf("got %+v want %+v", out, in)
	}
	if out.Rows != 24 || out.Cols != 80 {
		t.Fatalf("size %dx%d", out.Cols, out.Rows)
	}
}

func TestReadResultRoundTrip(t *testing.T) {
	in := Frame{
		Type:        TypeReadResult,
		Data:        []byte("chunk"),
		CursorNext:  12,
		Dropped:     4,
		AtEnd:       true,
		Epoch:       3,
		CursorAhead: true,
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != TypeReadResult || string(out.Data) != "chunk" || out.CursorNext != 12 || out.Dropped != 4 || !out.AtEnd || out.Epoch != 3 || !out.CursorAhead {
		t.Fatalf("got %+v", out)
	}
}

func TestReadFrameRejectsHugeLength(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("expected error")
	}
}
