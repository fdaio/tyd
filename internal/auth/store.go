package auth

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"tyd/internal/safefile"
)

type Principal struct {
	Name     string
	Pub      ed25519.PublicKey
	Global   map[Cap]bool
	Sessions map[string]map[Cap]bool
}

type Store struct {
	mu         sync.Mutex
	principals map[string]*Principal // keyed by public key encoding
	peerKeys   map[string]struct{}   // inbound peer pubs injected via EnsurePeer
}

func NewStore() *Store {
	return &Store{
		principals: make(map[string]*Principal),
		peerKeys:   make(map[string]struct{}),
	}
}

func (s *Store) Add(name string, pub ed25519.PublicKey, global []Cap) *Principal {
	p := &Principal{
		Name:     name,
		Pub:      append(ed25519.PublicKey(nil), pub...),
		Global:   make(map[Cap]bool),
		Sessions: make(map[string]map[Cap]bool),
	}
	for _, c := range global {
		p.Global[c] = true
	}
	s.mu.Lock()
	s.principals[EncodePublic(p.Pub)] = p
	s.mu.Unlock()
	return p
}

// EnsurePeer upserts a peer principal by public key (preserves session grants).
func (s *Store) EnsurePeer(name string, pub ed25519.PublicKey, caps []Cap) *Principal {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := EncodePublic(pub)
	if p, ok := s.principals[key]; ok {
		if name != "" {
			p.Name = name
		}
		for _, c := range caps {
			p.Global[c] = true
		}
		out := *p
		out.Pub = append(ed25519.PublicKey(nil), p.Pub...)
		return &out
	}
	p := &Principal{
		Name:     name,
		Pub:      append(ed25519.PublicKey(nil), pub...),
		Global:   make(map[Cap]bool),
		Sessions: make(map[string]map[Cap]bool),
	}
	for _, c := range caps {
		p.Global[c] = true
	}
	s.principals[key] = p
	s.peerKeys[key] = struct{}{}
	out := *p
	out.Pub = append(ed25519.PublicKey(nil), p.Pub...)
	return &out
}

// DropUnlistedPeers removes EnsurePeer principals whose keys are not in keep.
func (s *Store) DropUnlistedPeers(keep []ed25519.PublicKey) {
	keepSet := make(map[string]struct{}, len(keep))
	for _, pub := range keep {
		keepSet[EncodePublic(pub)] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peerKeys == nil {
		s.peerKeys = make(map[string]struct{})
	}
	for k := range s.peerKeys {
		if _, ok := keepSet[k]; ok {
			continue
		}
		delete(s.principals, k)
		delete(s.peerKeys, k)
	}
}

// Has reports whether the store holds this public key, and therefore whether a
// connection presenting it would be authenticated.
func (s *Store) Has(encodedPub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.principals[strings.TrimSpace(encodedPub)]
	return ok
}

func (s *Store) Grant(pub ed25519.PublicKey, sessionID string, caps ...Cap) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.principals[EncodePublic(pub)]
	if !ok {
		return fmt.Errorf("unknown principal")
	}
	set := p.Sessions[sessionID]
	if set == nil {
		set = make(map[Cap]bool)
		p.Sessions[sessionID] = set
	}
	for _, c := range caps {
		set[c] = true
	}
	return nil
}

func (s *Store) Allow(p *Principal, cap Cap, sessionID string) bool {
	if p == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.principals[EncodePublic(p.Pub)]
	if !ok {
		return false
	}
	switch cap {
	case CapList, CapCreate:
		return cur.Global[cap]
	default:
		if sessionID == "" {
			return false
		}
		return cur.Sessions[sessionID][cap]
	}
}

func (s *Store) Authenticate(nonce, pub, sig []byte) (*Principal, error) {
	return s.AuthenticateBound(nonce, nil, pub, sig)
}

// AuthenticateBound verifies the auth response that arrived on this connection.
// The signature must cover the connection's channel binding, so a response
// taken from another connection does not verify here. That is what stops a
// peer from taking a challenge away from the daemon it was meant for, getting
// the client to sign it, and logging in here as the client.
func (s *Store) AuthenticateBound(nonce, binder, pub, sig []byte) (*Principal, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("untrusted public key")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), AuthPayload(nonce, binder), sig) {
		// A tyd older than the domain-separated auth signed the bare nonce.
		// Recognising that earns an actionable message. It is never accepted:
		// that signature is the one a peer can carry between daemons.
		if ed25519.Verify(ed25519.PublicKey(pub), nonce, sig) {
			return nil, fmt.Errorf("this client signs the auth protocol of an older tyd; " +
				"upgrade tyd on both ends to the same version")
		}
		return nil, fmt.Errorf("authentication failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.principals[EncodePublic(pub)]
	if !ok {
		return nil, fmt.Errorf("untrusted public key")
	}
	out := *p
	out.Pub = append(ed25519.PublicKey(nil), p.Pub...)
	return &out, nil
}

type filePrincipal struct {
	Name      string           `json:"name"`
	PublicKey string           `json:"public_key"`
	Allow     []Cap            `json:"allow"`
	Sessions  map[string][]Cap `json:"sessions,omitempty"`
}

type fileTrust struct {
	Principals []filePrincipal `json:"principals"`
}

func LoadStore(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc fileTrust
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("trust file: %w", err)
	}
	s := NewStore()
	for _, fp := range doc.Principals {
		pub, err := DecodePublic(fp.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("principal %q: %w", fp.Name, err)
		}
		p := s.Add(fp.Name, pub, fp.Allow)
		for sid, caps := range fp.Sessions {
			if err := s.Grant(p.Pub, sid, caps...); err != nil {
				return nil, err
			}
		}
	}
	if len(s.principals) == 0 {
		return nil, fmt.Errorf("trust file %s has no principals", path)
	}
	return s, nil
}

func WriteBootstrapTrust(path, name string, pub ed25519.PublicKey) error {
	doc := fileTrust{Principals: []filePrincipal{{
		Name:      name,
		PublicKey: EncodePublic(pub),
		Allow:     AllGlobal,
	}}}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFile(path, append(b, '\n'), 0o600)
}

func NewAdminStore() (ed25519.PrivateKey, *Store, error) {
	_, priv, err := Generate()
	if err != nil {
		return nil, nil, err
	}
	s := NewStore()
	s.Add("admin", priv.Public().(ed25519.PublicKey), AllGlobal)
	return priv, s, nil
}
