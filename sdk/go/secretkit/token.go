package secretkit

import (
	"context"
	"sync"
	"time"
)

// Token is the result of a successful login or refresh.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Scope        string    `json:"scope"`
	Expiry       time.Time `json:"expiry"`
}

// expiryLeeway refreshes tokens slightly early so they do not expire in flight.
const expiryLeeway = 30 * time.Second

func (t Token) expired(now time.Time) bool {
	return !t.Expiry.IsZero() && !now.Add(expiryLeeway).Before(t.Expiry)
}

// TokenSource supplies access tokens.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a TokenSource that always returns the same token.
type StaticToken string

func (s StaticToken) Token(context.Context) (string, error) { return string(s), nil }

type invalidator interface {
	invalidate(accessToken string)
}

// RefreshingTokenSource refreshes the access token when it is about to
// expire. OnRefresh, if set, is called with each new token so callers can
// persist it; refresh tokens rotate, so failing to persist means the next
// process has to log in again.
type RefreshingTokenSource struct {
	client    *Client
	clientID  string
	OnRefresh func(Token) error

	mu  sync.Mutex
	tok Token
}

// NewRefreshingTokenSource returns a source that starts from tok.
func (c *Client) NewRefreshingTokenSource(clientID string, tok Token) *RefreshingTokenSource {
	return &RefreshingTokenSource{client: c, clientID: clientID, tok: tok}
}

func (s *RefreshingTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tok.expired(s.client.now()) {
		return s.tok.AccessToken, nil
	}
	if s.tok.RefreshToken == "" {
		return "", ErrUnauthorized
	}
	next, err := s.client.RefreshToken(ctx, s.clientID, s.tok.RefreshToken)
	if err != nil {
		return "", err
	}
	s.tok = next
	if s.OnRefresh != nil {
		if err := s.OnRefresh(next); err != nil {
			return "", err
		}
	}
	return s.tok.AccessToken, nil
}

// Current returns the latest token, including any refreshes.
func (s *RefreshingTokenSource) Current() Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tok
}

func (s *RefreshingTokenSource) invalidate(accessToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Another goroutine may already have refreshed; only expire the token
	// that was actually rejected.
	if s.tok.AccessToken == accessToken {
		s.tok.Expiry = time.Unix(1, 0)
	}
}
