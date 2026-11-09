package endpointcache

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tyd/internal/auth"
)

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signedEntry(t *testing.T, peerID string, priv ed25519.PrivateKey, seq uint64) Entry {
	t.Helper()
	rec := auth.NewEndpointRecord(peerID, auth.EncodePublic(priv.Public().(ed25519.PublicKey)),
		"203.0.113.7:41234", "aabbccdd", "quic", []string{"203.0.113.7:41234"},
		time.Now(), 90*time.Second, seq)
	sig, err := rec.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	return Entry{PeerID: peerID, Record: rec, Sig: auth.EncodeBytes(sig)}
}

func TestStoreAndLoadVerifiedRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoint-cache.json")
	pub, priv := keyPair(t)
	e := signedEntry(t, "daemon-1", priv, 1)

	if err := Store(path, e, pub); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := f.Lookup("daemon-1")
	if !ok {
		t.Fatal("entry not found")
	}
	rec, ok := got.Verified(pub)
	if !ok {
		t.Fatal("stored record does not verify")
	}
	if rec.Addr != "203.0.113.7:41234" || rec.CertFP != "aabbccdd" {
		t.Fatalf("record %+v", rec)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm=%o, want 600", perm)
	}
}

func TestTamperedCacheIsIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoint-cache.json")
	pub, priv := keyPair(t)
	if err := Store(path, signedEntry(t, "daemon-1", priv, 1), pub); err != nil {
		t.Fatal(err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := f.Lookup("daemon-1")

	badSig := e
	badSig.Sig = auth.EncodeBytes(make([]byte, ed25519.SignatureSize))
	if _, ok := badSig.Verified(pub); ok {
		t.Fatal("a forged signature verified")
	}

	moved := e
	moved.Record.Addr = "198.51.100.9:1"
	if _, ok := moved.Verified(pub); ok {
		t.Fatal("an altered address verified")
	}

	otherPub, _ := keyPair(t)
	if _, ok := e.Verified(otherPub); ok {
		t.Fatal("a record verified against the wrong peer key")
	}
}

func TestWrongPeerIDIsIgnored(t *testing.T) {
	pub, priv := keyPair(t)
	e := signedEntry(t, "daemon-1", priv, 1)
	e.PeerID = "daemon-2"
	if _, ok := e.Verified(pub); ok {
		t.Fatal("an entry naming a different peer verified")
	}
	if err := Store(filepath.Join(t.TempDir(), "cache.json"), e, pub); err == nil {
		t.Fatal("an entry naming a different peer was stored")
	}
}

func TestUnpairedPeerHasNoEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Lookup("never-paired"); ok {
		t.Fatal("unexpected entry")
	}
}

func TestCorruptCacheIsReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("corrupt cache loaded")
	}
	pub, priv := keyPair(t)
	if err := Store(path, signedEntry(t, "daemon-1", priv, 1), pub); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Lookup("daemon-1"); !ok {
		t.Fatal("entry missing after replacing a corrupt cache")
	}
}

func TestUpsertKeepsOneEntryPerPeer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	pub, priv := keyPair(t)
	for seq := uint64(1); seq <= 2; seq++ {
		if err := Store(path, signedEntry(t, "daemon-1", priv, seq), pub); err != nil {
			t.Fatal(err)
		}
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Peers) != 1 {
		t.Fatalf("entries=%d, want 1", len(f.Peers))
	}
	if f.Peers[0].Record.Seq != 2 {
		t.Fatalf("seq=%d, want 2", f.Peers[0].Record.Seq)
	}
}
