// Package cpclient talks to a tyd Control Panel over HTTP.
package cpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tyd/internal/controlpanel"
)

const DefaultPlatform = "https://app.getfda.dev"

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func New(baseURL string) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = DefaultPlatform
	}
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *Client) Register(publicKey, approvalMode string) (*controlpanel.RegisterResponse, error) {
	return c.RegisterOpts(publicKey, approvalMode, false)
}

func (c *Client) RegisterOpts(publicKey, approvalMode string, force bool) (*controlpanel.RegisterResponse, error) {
	var out controlpanel.RegisterResponse
	if err := c.post("/v1/register", controlpanel.RegisterRequest{
		PublicKey:    publicKey,
		ApprovalMode: approvalMode,
		Force:        force,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RecoverRegistration re-reads this daemon's registration from the CP by
// public key, without stating an approval mode, so the recorded mode survives.
// Used when the local peers.json is lost or unreadable.
func (c *Client) RecoverRegistration(publicKey string) (*controlpanel.RegisterResponse, error) {
	return c.RegisterOpts(publicKey, "", false)
}

func (c *Client) Restore(req controlpanel.RestoreRequest) (*controlpanel.RegisterResponse, error) {
	var out controlpanel.RegisterResponse
	if err := c.post("/v1/restore", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateInvite(daemonID, publicKey string) (*controlpanel.CreateInviteResponse, error) {
	var out controlpanel.CreateInviteResponse
	if err := c.post("/v1/invites", controlpanel.CreateInviteRequest{
		DaemonID:  daemonID,
		PublicKey: publicKey,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Accept(token, publicKey, nickname string) (*controlpanel.AcceptResponse, error) {
	var out controlpanel.AcceptResponse
	if err := c.post("/v1/accept", controlpanel.AcceptRequest{
		Token:     token,
		PublicKey: publicKey,
		Nickname:  nickname,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ListPeers(daemonID, publicKey string) ([]controlpanel.Peer, error) {
	u := c.BaseURL + "/v1/daemons/" + url.PathEscape(daemonID) + "/peers?public_key=" + url.QueryEscape(publicKey)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("cp list peers: %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	var wrap struct {
		Peers []controlpanel.Peer `json:"peers"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, err
	}
	return wrap.Peers, nil
}

func (c *Client) PublishEndpoint(daemonID, publicKey, addr, certFP string, ttl time.Duration) error {
	return c.PublishEndpointFull(daemonID, controlpanel.PublishEndpointRequest{
		PublicKey: publicKey,
		Addr:      addr,
		CertFP:    certFP,
		TTLSeconds: func() int {
			if ttl > 0 {
				return int(ttl / time.Second)
			}
			return 0
		}(),
	})
}

func (c *Client) PublishEndpointFull(daemonID string, req controlpanel.PublishEndpointRequest) error {
	var out controlpanel.EndpointResponse
	return c.put("/v1/daemons/"+url.PathEscape(daemonID)+"/endpoint", req, &out)
}

func (c *Client) GetEndpoint(daemonID string) (addr, certFP string, err error) {
	ep, err := c.GetEndpointFull(daemonID)
	if err != nil {
		return "", "", err
	}
	return ep.Addr, ep.CertFP, nil
}

func (c *Client) GetEndpointFull(daemonID string) (*controlpanel.EndpointResponse, error) {
	u := c.BaseURL + "/v1/daemons/" + url.PathEscape(daemonID) + "/endpoint"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("cp get endpoint: %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	var out controlpanel.EndpointResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RevokeInvite(token, daemonID, publicKey string) error {
	return c.post("/v1/invites/revoke", controlpanel.RevokeInviteRequest{
		Token:     token,
		DaemonID:  daemonID,
		PublicKey: publicKey,
	}, nil)
}

func (c *Client) RevokePeer(daemonID, publicKey, peerID string) error {
	u := c.BaseURL + "/v1/daemons/" + url.PathEscape(daemonID) + "/peers/" + url.PathEscape(peerID) +
		"?public_key=" + url.QueryEscape(publicKey)
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return fmt.Errorf("cp revoke peer: %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) put(path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, c.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return fmt.Errorf("cp %s: %s: %s", path, res.Status, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (c *Client) post(path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	res, err := c.HTTPClient.Post(c.BaseURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return fmt.Errorf("cp %s: %s: %s", path, res.Status, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}
