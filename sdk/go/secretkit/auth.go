package secretkit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/WenxueWu0216/SecretKit/sdk/go/api"
)

// Default scopes requested by StartDeviceAuth when none are given.
const (
	ScopeRead  = "secrets:read"
	ScopeWrite = "secrets:write"
)

// defaultPollInterval is the RFC 8628 default when the server sends none.
const defaultPollInterval = 5 * time.Second

// DeviceAuth is an in-progress device authorization. The PKCE verifier
// lives only in this struct and is never sent until the token exchange.
type DeviceAuth struct {
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresAt               time.Time
	Interval                time.Duration

	clientID   string
	deviceCode string
	verifier   string
}

// NewPKCEVerifier returns a random 43-character verifier (RFC 7636).
func NewPKCEVerifier() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// PKCEChallenge returns the S256 challenge for verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// StartDeviceAuth requests a device and user code.
func (c *Client) StartDeviceAuth(ctx context.Context, clientID, scope string) (*DeviceAuth, error) {
	verifier := NewPKCEVerifier()
	body := api.DeviceCodeRequest{
		ClientId:            clientID,
		CodeChallenge:       PKCEChallenge(verifier),
		CodeChallengeMethod: api.S256,
	}
	if scope != "" {
		body.Scope = &scope
	}
	resp, err := c.api.RequestDeviceCodeWithFormdataBodyWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.HTTPResponse, resp.JSON400, resp.JSON429)
	}
	r := resp.JSON200
	da := &DeviceAuth{
		UserCode:        r.UserCode,
		VerificationURI: r.VerificationUri,
		ExpiresAt:       c.now().Add(time.Duration(r.ExpiresIn) * time.Second),
		Interval:        time.Duration(r.Interval) * time.Second,
		clientID:        clientID,
		deviceCode:      r.DeviceCode,
		verifier:        verifier,
	}
	if r.VerificationUriComplete != nil {
		da.VerificationURIComplete = *r.VerificationUriComplete
	}
	if da.Interval <= 0 {
		da.Interval = defaultPollInterval
	}
	return da, nil
}

// PollToken waits for the user to approve da, honoring the polling
// interval and slow_down responses. It returns ErrAccessDenied,
// ErrExpiredToken, or a context error if the flow does not complete.
func (c *Client) PollToken(ctx context.Context, da *DeviceAuth) (Token, error) {
	interval := da.Interval
	for {
		if !c.now().Before(da.ExpiresAt) {
			return Token{}, &APIError{StatusCode: 400, Code: "expired_token", Description: "device code expired before approval"}
		}
		if err := c.sleep(ctx, interval); err != nil {
			return Token{}, err
		}
		tok, err := c.exchange(ctx, api.TokenRequest{
			ClientId:     da.clientID,
			GrantType:    api.TokenRequestGrantTypeUrnIetfParamsOauthGrantTypeDeviceCode,
			DeviceCode:   &da.deviceCode,
			CodeVerifier: &da.verifier,
		})
		switch {
		case errors.Is(err, ErrAuthorizationPending):
			continue
		case errors.Is(err, ErrSlowDown):
			interval += 5 * time.Second
			continue
		}
		return tok, err
	}
}

// RefreshToken exchanges a refresh token for a new token pair. The old
// refresh token is invalid afterwards.
func (c *Client) RefreshToken(ctx context.Context, clientID, refreshToken string) (Token, error) {
	return c.exchange(ctx, api.TokenRequest{
		ClientId:     clientID,
		GrantType:    api.TokenRequestGrantTypeRefreshToken,
		RefreshToken: &refreshToken,
	})
}

func (c *Client) exchange(ctx context.Context, req api.TokenRequest) (Token, error) {
	resp, err := c.api.RequestTokenWithFormdataBodyWithResponse(ctx, req)
	if err != nil {
		return Token{}, err
	}
	if resp.JSON200 == nil {
		return Token{}, newAPIError(resp.HTTPResponse, resp.JSON400, resp.JSON429)
	}
	r := resp.JSON200
	return Token{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
		Scope:        r.Scope,
		Expiry:       c.now().Add(time.Duration(r.ExpiresIn) * time.Second),
	}, nil
}

// RevokeToken revokes a refresh token (ending the session) or an access token.
func (c *Client) RevokeToken(ctx context.Context, token string) error {
	resp, err := c.api.RevokeTokenWithFormdataBodyWithResponse(ctx, api.RevokeRequest{Token: token})
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return newAPIError(resp.HTTPResponse, resp.JSON400)
	}
	return nil
}

// ApproveDevice approves or denies a user code. The mock server exposes
// this in place of a browser consent page; real deployments would not.
func (c *Client) ApproveDevice(ctx context.Context, userCode string, approve bool) error {
	action := api.Deny
	if approve {
		action = api.Approve
	}
	resp, err := c.api.VerifyDeviceCodeWithFormdataBodyWithResponse(ctx, api.DeviceVerifyRequest{UserCode: userCode, Action: action})
	if err != nil {
		return err
	}
	if resp.StatusCode() != 204 {
		return newAPIError(resp.HTTPResponse, resp.JSON400, resp.JSON404)
	}
	return nil
}
