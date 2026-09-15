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
	var out controlpanel.RegisterResponse
	if err := c.post("/v1/register", controlpanel.RegisterRequest{
		PublicKey:    publicKey,
		ApprovalMode: approvalMode,
	}, &out); err != nil {
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
