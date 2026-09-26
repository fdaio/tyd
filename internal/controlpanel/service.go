// Package controlpanel is a minimal Control Panel for tyd peer pairing.
// It stores registration and pairing metadata (ids + public keys) only.
// It must never store session or TTY content.
package controlpanel

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"tyd/internal/relay"
	"tyd/scripts"
)

const (
	InviteTTL          = 10 * time.Minute
	DefaultEndpointTTL = 90 * time.Second
	ApprovalFull       = "full"
	ApprovalPre        = "pre"
	ApprovalPost       = "post"
	DefaultApproval    = ApprovalFull
	idBytes            = 8
	inviteTokenBytes   = 16
)

var (
	ErrNotFound         = errors.New("not found")
	ErrInviteExpired    = errors.New("invite expired")
	ErrInviteUsed       = errors.New("invite already used")
	ErrInvalidApproval  = errors.New("invalid approval mode")
	ErrInvalidPublicKey = errors.New("invalid public key")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrAlreadyPaired    = errors.New("already paired")
	ErrNotPaired        = errors.New("not paired")
	maxJSONBody         = int64(1 << 20)
)

// Service is an in-memory CP suitable for local runs and tests.
type Service struct {
	mu         sync.Mutex
	daemons    map[string]*Daemon   // id -> daemon
	byPub      map[string]string    // public_key -> id
	invites    map[string]*Invite   // token -> invite
	endpoints  map[string]*Endpoint // daemon id -> current endpoint (ephemeral signaling only)
	now        func() time.Time
	baseURL    string // optional; used when building public URLs
	releaseDir string // optional; directory served at /releases/ (install binaries)
	relayHub   *relay.Hub
}

// Endpoint is ephemeral dial signaling for the data plane.
// CP must never store session/TTY content — only addr / cert fingerprint hints.
type Endpoint struct {
	DaemonID   string    `json:"daemon_id"`
	PublicKey  string    `json:"public_key"`
	Addr       string    `json:"addr"`
	CertFP     string    `json:"cert_fp"`
	Transport  string    `json:"transport,omitempty"` // tls|quic; default tls for older clients
	Candidates []string  `json:"candidates,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type PublishEndpointRequest struct {
	PublicKey  string   `json:"public_key"`
	Addr       string   `json:"addr"`
	CertFP     string   `json:"cert_fp"`
	Transport  string   `json:"transport,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
}

type EndpointResponse struct {
	Addr       string    `json:"addr"`
	CertFP     string    `json:"cert_fp"`
	Transport  string    `json:"transport,omitempty"`
	Candidates []string  `json:"candidates,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Daemon struct {
	ID           string    `json:"id"`
	PublicKey    string    `json:"public_key"`
	ApprovalMode string    `json:"approval_mode"`
	RegisteredAt time.Time `json:"registered_at"`
	Peers        []Peer    `json:"peers"`
}

type Peer struct {
	ID        string    `json:"id"`
	PublicKey string    `json:"public_key"`
	Nickname  string    `json:"nickname,omitempty"`
	PairedAt  time.Time `json:"paired_at"`
	Direction string    `json:"direction"` // "inbound" on server, "outbound" on client
}

type Invite struct {
	Token     string    `json:"token"`
	DaemonID  string    `json:"daemon_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

type RegisterRequest struct {
	PublicKey    string `json:"public_key"`
	ApprovalMode string `json:"approval_mode,omitempty"`
	Force        bool   `json:"force,omitempty"` // replace existing registration (new id; drops old peers)
}

type RegisterResponse struct {
	ID           string `json:"id"`
	URL          string `json:"url"`
	ApprovalMode string `json:"approval_mode"`
	PublicKey    string `json:"public_key"`
}

// RestoreRequest rehydrates a daemon that already exists in local peers.json
// onto a CP that lost in-memory state (same id + public key).
type RestoreRequest struct {
	ID           string `json:"id"`
	PublicKey    string `json:"public_key"`
	ApprovalMode string `json:"approval_mode,omitempty"`
	Peers        []Peer `json:"peers,omitempty"`
}

type CreateInviteRequest struct {
	DaemonID  string `json:"daemon_id"`
	PublicKey string `json:"public_key"` // must match registered daemon
}

type CreateInviteResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	DaemonID  string    `json:"daemon_id"`
}

type AcceptRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"public_key"`
	Nickname  string `json:"nickname,omitempty"` // how acceptor labels the inviter
}

type AcceptResponse struct {
	SelfID        string `json:"self_id"`
	SelfPublicKey string `json:"self_public_key"`
	PeerID        string `json:"peer_id"`
	PeerPublicKey string `json:"peer_public_key"`
	PeerNickname  string `json:"peer_nickname,omitempty"`
}

type RevokeInviteRequest struct {
	Token     string `json:"token"`
	DaemonID  string `json:"daemon_id"`
	PublicKey string `json:"public_key"`
}

func New() *Service {
	return &Service{
		daemons:   make(map[string]*Daemon),
		byPub:     make(map[string]string),
		invites:   make(map[string]*Invite),
		endpoints: make(map[string]*Endpoint),
		now:       time.Now,
		relayHub:  relay.NewHub(),
	}
}

func (s *Service) SetBaseURL(u string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseURL = strings.TrimRight(u, "/")
}

// SetReleaseDir sets the directory of install archives served under /releases/.
// Empty disables the route (requests return 404).
func (s *Service) SetReleaseDir(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseDir = strings.TrimSpace(dir)
}

func (s *Service) SetNow(fn func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = fn
}

func NormalizeApproval(mode string) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return DefaultApproval, nil
	}
	switch mode {
	case ApprovalFull, ApprovalPre, ApprovalPost:
		return mode, nil
	default:
		return "", ErrInvalidApproval
	}
}

func (s *Service) Register(req RegisterRequest) (*RegisterResponse, error) {
	pub := strings.TrimSpace(req.PublicKey)
	if pub == "" {
		return nil, ErrInvalidPublicKey
	}
	mode, err := NormalizeApproval(req.ApprovalMode)
	if err != nil {
		return nil, err
	}
	// An empty mode means "whatever is already on record". Recovering a lost
	// peers.json must not silently relax a pre/post daemon to full.
	stated := strings.TrimSpace(req.ApprovalMode) != ""

	s.mu.Lock()
	defer s.mu.Unlock()

	if id, ok := s.byPub[pub]; ok {
		if !req.Force {
			d := s.daemons[id]
			if stated {
				d.ApprovalMode = mode
			}
			return s.registerRespLocked(d), nil
		}
		s.deleteDaemonLocked(id)
	}

	id, err := randomHex(idBytes)
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		ID:           id,
		PublicKey:    pub,
		ApprovalMode: mode,
		RegisteredAt: s.now(),
		Peers:        nil,
	}
	s.daemons[id] = d
	s.byPub[pub] = id
	return s.registerRespLocked(d), nil
}

// Restore upserts a daemon by the client-known id so tyd up can reuse
// peers.json after a CP restart without minting a new registration.
func (s *Service) Restore(req RestoreRequest) (*RegisterResponse, error) {
	id := strings.TrimSpace(req.ID)
	pub := strings.TrimSpace(req.PublicKey)
	if id == "" || pub == "" {
		return nil, ErrInvalidPublicKey
	}
	mode, err := NormalizeApproval(req.ApprovalMode)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existingID, ok := s.byPub[pub]; ok && existingID != id {
		return nil, fmt.Errorf("public key already registered as %s; use register --force to replace", existingID)
	}
	if d, ok := s.daemons[id]; ok {
		if d.PublicKey != pub {
			return nil, ErrUnauthorized
		}
		d.ApprovalMode = mode
		if err := s.applyPeersLocked(d, req.Peers); err != nil {
			return nil, err
		}
		return s.registerRespLocked(d), nil
	}

	d := &Daemon{
		ID:           id,
		PublicKey:    pub,
		ApprovalMode: mode,
		RegisteredAt: s.now(),
	}
	s.daemons[id] = d
	s.byPub[pub] = id
	if err := s.applyPeersLocked(d, req.Peers); err != nil {
		delete(s.daemons, id)
		delete(s.byPub, pub)
		return nil, err
	}
	return s.registerRespLocked(d), nil
}

func (s *Service) deleteDaemonLocked(id string) {
	d, ok := s.daemons[id]
	if !ok {
		return
	}
	delete(s.byPub, d.PublicKey)
	delete(s.daemons, id)
	delete(s.endpoints, id)
	for _, other := range s.daemons {
		filtered := other.Peers[:0]
		for _, p := range other.Peers {
			if p.ID == id {
				continue
			}
			filtered = append(filtered, p)
		}
		other.Peers = filtered
	}
}

func (s *Service) applyPeersLocked(self *Daemon, peers []Peer) error {
	self.Peers = nil
	for _, p := range peers {
		p.ID = strings.TrimSpace(p.ID)
		p.PublicKey = strings.TrimSpace(p.PublicKey)
		if p.ID == "" || p.PublicKey == "" || p.ID == self.ID {
			continue
		}
		dir := strings.TrimSpace(p.Direction)
		if dir == "" {
			dir = "outbound"
		}
		peerDaemon, err := s.ensureDaemonWithIDLocked(p.ID, p.PublicKey, DefaultApproval)
		if err != nil {
			return err
		}
		// Local peer list may carry a stale id if CP already mapped the pub elsewhere.
		p.ID = peerDaemon.ID
		p.Direction = dir
		if p.PairedAt.IsZero() {
			p.PairedAt = s.now()
		}
		self.Peers = append(self.Peers, p)
		s.ensureReciprocalPeerLocked(self, peerDaemon, oppositeDirection(dir), p.PairedAt)
	}
	return nil
}

func oppositeDirection(dir string) string {
	if dir == "inbound" {
		return "outbound"
	}
	return "inbound"
}

func (s *Service) ensureDaemonWithIDLocked(id, pub, mode string) (*Daemon, error) {
	if d, ok := s.daemons[id]; ok {
		if d.PublicKey != pub {
			return nil, ErrUnauthorized
		}
		return d, nil
	}
	if existingID, ok := s.byPub[pub]; ok {
		return s.daemons[existingID], nil
	}
	d := &Daemon{
		ID:           id,
		PublicKey:    pub,
		ApprovalMode: mode,
		RegisteredAt: s.now(),
	}
	s.daemons[id] = d
	s.byPub[pub] = id
	return d, nil
}

func (s *Service) ensureReciprocalPeerLocked(self, peer *Daemon, dir string, pairedAt time.Time) {
	if peerIndex(peer.Peers, self.ID) >= 0 {
		return
	}
	peer.Peers = append(peer.Peers, Peer{
		ID:        self.ID,
		PublicKey: self.PublicKey,
		PairedAt:  pairedAt,
		Direction: dir,
	})
}

func (s *Service) registerRespLocked(d *Daemon) *RegisterResponse {
	url := d.ID
	if s.baseURL != "" {
		url = s.baseURL + "/" + d.ID
	}
	return &RegisterResponse{
		ID:           d.ID,
		URL:          url,
		ApprovalMode: d.ApprovalMode,
		PublicKey:    d.PublicKey,
	}
}

func (s *Service) CreateInvite(req CreateInviteRequest) (*CreateInviteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneInvitesLocked()

	d, ok := s.daemons[req.DaemonID]
	if !ok {
		return nil, ErrNotFound
	}
	if d.PublicKey != strings.TrimSpace(req.PublicKey) {
		return nil, ErrUnauthorized
	}
	token, err := randomHex(inviteTokenBytes)
	if err != nil {
		return nil, err
	}
	inv := &Invite{
		Token:     token,
		DaemonID:  d.ID,
		ExpiresAt: s.now().Add(InviteTTL),
	}
	s.invites[token] = inv
	return &CreateInviteResponse{
		Token:     token,
		ExpiresAt: inv.ExpiresAt,
		DaemonID:  d.ID,
	}, nil
}

func (s *Service) Accept(req AcceptRequest) (*AcceptResponse, error) {
	pub := strings.TrimSpace(req.PublicKey)
	if pub == "" {
		return nil, ErrInvalidPublicKey
	}
	nick := strings.TrimSpace(req.Nickname)

	s.mu.Lock()
	defer s.mu.Unlock()

	tok := strings.TrimSpace(req.Token)
	inv, ok := s.invites[tok]
	if !ok {
		return nil, ErrNotFound
	}
	if inv.Used {
		return nil, ErrInviteUsed
	}
	if !s.now().Before(inv.ExpiresAt) {
		delete(s.invites, tok)
		return nil, ErrInviteExpired
	}
	s.pruneInvitesLocked()
	server, ok := s.daemons[inv.DaemonID]
	if !ok {
		return nil, ErrNotFound
	}
	if server.PublicKey == pub {
		return nil, fmt.Errorf("cannot accept own invite")
	}

	client, err := s.ensureDaemonLocked(pub, DefaultApproval)
	if err != nil {
		return nil, err
	}

	// Unidirectional: client may operate on server.
	if peerIndex(server.Peers, client.ID) >= 0 || peerIndex(client.Peers, server.ID) >= 0 {
		return nil, ErrAlreadyPaired
	}
	now := s.now()
	server.Peers = append(server.Peers, Peer{
		ID:        client.ID,
		PublicKey: client.PublicKey,
		Nickname:  "",
		PairedAt:  now,
		Direction: "inbound",
	})
	client.Peers = append(client.Peers, Peer{
		ID:        server.ID,
		PublicKey: server.PublicKey,
		Nickname:  nick,
		PairedAt:  now,
		Direction: "outbound",
	})
	inv.Used = true

	return &AcceptResponse{
		SelfID:        client.ID,
		SelfPublicKey: client.PublicKey,
		PeerID:        server.ID,
		PeerPublicKey: server.PublicKey,
		PeerNickname:  nick,
	}, nil
}

func (s *Service) ensureDaemonLocked(pub, mode string) (*Daemon, error) {
	if id, ok := s.byPub[pub]; ok {
		return s.daemons[id], nil
	}
	id, err := randomHex(idBytes)
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		ID:           id,
		PublicKey:    pub,
		ApprovalMode: mode,
		RegisteredAt: s.now(),
	}
	s.daemons[id] = d
	s.byPub[pub] = id
	return d, nil
}

func (s *Service) GetDaemon(id string) (*Daemon, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.daemons[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := *d
	out.Peers = append([]Peer(nil), d.Peers...)
	return &out, nil
}

func (s *Service) ListPeers(daemonID, publicKey string) ([]Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.daemons[daemonID]
	if !ok {
		return nil, ErrNotFound
	}
	if d.PublicKey != strings.TrimSpace(publicKey) {
		return nil, ErrUnauthorized
	}
	return append([]Peer(nil), d.Peers...), nil
}

func (s *Service) pruneInvitesLocked() {
	now := s.now()
	for tok, inv := range s.invites {
		if inv.Used || !now.Before(inv.ExpiresAt) {
			delete(s.invites, tok)
		}
	}
}

func (s *Service) RevokeInvite(req RevokeInviteRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneInvitesLocked()

	tok := strings.TrimSpace(req.Token)
	inv, ok := s.invites[tok]
	if !ok {
		return ErrNotFound
	}
	d, ok := s.daemons[inv.DaemonID]
	if !ok {
		delete(s.invites, tok)
		return ErrNotFound
	}
	if d.ID != strings.TrimSpace(req.DaemonID) || d.PublicKey != strings.TrimSpace(req.PublicKey) {
		return ErrUnauthorized
	}
	if inv.Used {
		return ErrInviteUsed
	}
	delete(s.invites, tok)
	return nil
}

func (s *Service) RevokePeer(daemonID, publicKey, peerID string) error {
	daemonID = strings.TrimSpace(daemonID)
	peerID = strings.TrimSpace(peerID)
	publicKey = strings.TrimSpace(publicKey)
	if daemonID == "" || peerID == "" {
		return ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	self, ok := s.daemons[daemonID]
	if !ok {
		return ErrNotFound
	}
	if self.PublicKey != publicKey {
		return ErrUnauthorized
	}
	other, ok := s.daemons[peerID]
	if !ok {
		return ErrNotFound
	}
	si := peerIndex(self.Peers, peerID)
	oi := peerIndex(other.Peers, daemonID)
	if si < 0 && oi < 0 {
		return ErrNotPaired
	}
	if si >= 0 {
		self.Peers = append(self.Peers[:si], self.Peers[si+1:]...)
	}
	if oi >= 0 {
		other.Peers = append(other.Peers[:oi], other.Peers[oi+1:]...)
	}
	return nil
}

func (s *Service) PublishEndpoint(daemonID string, req PublishEndpointRequest) (*EndpointResponse, error) {
	pub := strings.TrimSpace(req.PublicKey)
	addr := strings.TrimSpace(req.Addr)
	fp := strings.TrimSpace(strings.ToLower(req.CertFP))
	if pub == "" {
		return nil, ErrInvalidPublicKey
	}
	if addr == "" || fp == "" {
		return nil, fmt.Errorf("addr and cert_fp required")
	}
	ttl := DefaultEndpointTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.daemons[daemonID]
	if !ok {
		return nil, ErrNotFound
	}
	if d.PublicKey != pub {
		return nil, ErrUnauthorized
	}
	tr := strings.TrimSpace(strings.ToLower(req.Transport))
	if tr == "" {
		tr = "tls"
	}
	cands := uniqueNonEmpty(req.Candidates)
	ep := &Endpoint{
		DaemonID:   d.ID,
		PublicKey:  pub,
		Addr:       addr,
		CertFP:     fp,
		Transport:  tr,
		Candidates: cands,
		ExpiresAt:  s.now().Add(ttl),
	}
	s.endpoints[d.ID] = ep
	return &EndpointResponse{
		Addr:       ep.Addr,
		CertFP:     ep.CertFP,
		Transport:  ep.Transport,
		Candidates: append([]string(nil), ep.Candidates...),
		ExpiresAt:  ep.ExpiresAt,
	}, nil
}

func (s *Service) GetEndpoint(daemonID string) (*EndpointResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep, ok := s.endpoints[daemonID]
	if !ok {
		return nil, ErrNotFound
	}
	if !s.now().Before(ep.ExpiresAt) {
		delete(s.endpoints, daemonID)
		return nil, ErrNotFound
	}
	return &EndpointResponse{
		Addr:       ep.Addr,
		CertFP:     ep.CertFP,
		Transport:  ep.Transport,
		Candidates: append([]string(nil), ep.Candidates...),
		ExpiresAt:  ep.ExpiresAt,
	}, nil
}

func uniqueNonEmpty(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func peerIndex(peers []Peer, id string) int {
	for i, p := range peers {
		if p.ID == id {
			return i
		}
	}
	return -1
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Handler returns an http.Handler implementing the CP HTTP API.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/install.sh", handleInstallScript)
	s.mu.Lock()
	relDir := s.releaseDir
	s.mu.Unlock()
	if relDir != "" {
		mux.Handle("/releases/", noCacheFileServer(http.Dir(relDir)))
	}
	// Dual-NAT rendezvous (WebSocket). Same process as pairing, but TTY bytes
	// never touch the pairing API — blind splice only.
	mux.Handle("/relay", s.relayHub.Handler())
	mux.Handle("/relay/", http.StripPrefix("/relay", s.relayHub.Handler()))
	mux.HandleFunc("/v1/register", s.handleRegister)
	mux.HandleFunc("/v1/restore", s.handleRestore)
	mux.HandleFunc("/v1/invites/revoke", s.handleRevokeInvite)
	mux.HandleFunc("/v1/invites", s.handleCreateInvite)
	mux.HandleFunc("/v1/accept", s.handleAccept)
	mux.HandleFunc("/v1/daemons/", s.handleDaemon)
	return mux
}

func (s *Service) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req RegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	resp, err := s.Register(req)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req RestoreRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	resp, err := s.Restore(req)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req CreateInviteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	resp, err := s.CreateInvite(req)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req RevokeInviteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.RevokeInvite(req); err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Service) handleAccept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req AcceptRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	resp, err := s.Accept(req)
	if err != nil {
		writeServiceErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleDaemon(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/daemons/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		d, err := s.GetDaemon(id)
		if err != nil {
			writeServiceErr(w, err)
			return
		}
		// Public metadata only (no private material beyond published public key).
		writeJSON(w, http.StatusOK, map[string]any{
			"id":            d.ID,
			"public_key":    d.PublicKey,
			"approval_mode": d.ApprovalMode,
			"registered_at": d.RegisteredAt,
		})
		return
	}
	if len(parts) == 2 && parts[1] == "peers" {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		pub := r.URL.Query().Get("public_key")
		peers, err := s.ListPeers(id, pub)
		if err != nil {
			writeServiceErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"peers": peers})
		return
	}
	if len(parts) == 3 && parts[1] == "peers" {
		if r.Method != http.MethodDelete {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		pub := r.URL.Query().Get("public_key")
		if err := s.RevokePeer(id, pub, parts[2]); err != nil {
			writeServiceErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
		return
	}
	if len(parts) == 2 && parts[1] == "endpoint" {
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			var req PublishEndpointRequest
			if err := decodeJSON(r, &req); err != nil {
				writeErr(w, http.StatusBadRequest, "invalid json")
				return
			}
			resp, err := s.PublishEndpoint(id, req)
			if err != nil {
				writeServiceErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		case http.MethodGet:
			resp, err := s.GetEndpoint(id)
			if err != nil {
				writeServiceErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}
	writeErr(w, http.StatusNotFound, "not found")
}

func handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	body := scripts.InstallSH
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func writeServiceErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrInviteExpired):
		writeErr(w, http.StatusGone, err.Error())
	case errors.Is(err, ErrInviteUsed), errors.Is(err, ErrAlreadyPaired), errors.Is(err, ErrNotPaired):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrUnauthorized):
		writeErr(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, ErrInvalidApproval), errors.Is(err, ErrInvalidPublicKey):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, maxJSONBody)).Decode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ListenAndServe starts the CP HTTP server on addr (e.g. "127.0.0.1:0").
func ListenAndServe(addr string, s *Service) (net.Addr, *http.Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	if s.baseURL == "" {
		s.SetBaseURL("http://" + ln.Addr().String())
	}
	srv := &http.Server{Handler: s.Handler()}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr(), srv, nil
}

// noCacheFileServer serves install archives without long-lived CDN caching.
func noCacheFileServer(root http.FileSystem) http.Handler {
	files := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
		http.StripPrefix("/releases/", files).ServeHTTP(w, r)
	})
}
