package server

import (
	"errors"
	"slices"
	"sync"
	"time"
)

var (
	errTokenInvalid = errors.New("token is invalid or revoked")
	errTokenExpired = errors.New("token expired")
)

// TokenPair is returned to clients. Only hashes are kept server-side.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
	Scopes       []string
}

type accessRecord struct {
	family    string
	scopes    []string
	expiresAt time.Time // zero means it never expires (dev tokens)
}

type refreshRecord struct {
	family    string
	clientID  string
	scopes    []string
	expiresAt time.Time
	used      bool
}

// TokenStore issues short-lived access tokens and rotating refresh tokens.
// Every login starts a token family; presenting an already-rotated refresh
// token revokes the whole family, since it means the token leaked.
type TokenStore struct {
	mu         sync.Mutex
	now        func() time.Time
	accessTTL  time.Duration
	refreshTTL time.Duration
	access     map[string]*accessRecord
	refresh    map[string]*refreshRecord
	revoked    map[string]bool
}

func NewTokenStore(now func() time.Time, accessTTL, refreshTTL time.Duration) *TokenStore {
	return &TokenStore{
		now:        now,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		access:     make(map[string]*accessRecord),
		refresh:    make(map[string]*refreshRecord),
		revoked:    make(map[string]bool),
	}
}

// Issue starts a new token family.
func (s *TokenStore) Issue(clientID string, scopes []string) TokenPair {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issueLocked(randomToken(16), clientID, scopes)
}

func (s *TokenStore) issueLocked(family, clientID string, scopes []string) TokenPair {
	s.sweepLocked()
	now := s.now()
	access := randomToken(32)
	refresh := randomToken(32)
	s.access[hashToken(access)] = &accessRecord{family: family, scopes: scopes, expiresAt: now.Add(s.accessTTL)}
	s.refresh[hashToken(refresh)] = &refreshRecord{family: family, clientID: clientID, scopes: scopes, expiresAt: now.Add(s.refreshTTL)}
	return TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresIn: s.accessTTL, Scopes: scopes}
}

// Refresh rotates a refresh token.
func (s *TokenStore) Refresh(clientID, refreshToken string) (TokenPair, error) {
	if refreshToken == "" {
		return TokenPair{}, oauthErr(CodeInvalidRequest, "refresh_token is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.refresh[hashToken(refreshToken)]
	if rec == nil || s.revoked[rec.family] || rec.clientID != clientID {
		return TokenPair{}, oauthErr(CodeInvalidGrant, "unknown refresh_token")
	}
	if rec.used {
		s.revoked[rec.family] = true
		return TokenPair{}, oauthErr(CodeInvalidGrant, "refresh_token reuse detected; session revoked")
	}
	if !s.now().Before(rec.expiresAt) {
		return TokenPair{}, oauthErr(CodeInvalidGrant, "refresh_token expired")
	}
	rec.used = true
	return s.issueLocked(rec.family, clientID, rec.scopes), nil
}

// Authenticate resolves an access token to its scopes.
func (s *TokenStore) Authenticate(accessToken string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.access[hashToken(accessToken)]
	if rec == nil || s.revoked[rec.family] {
		return nil, errTokenInvalid
	}
	if !rec.expiresAt.IsZero() && !s.now().Before(rec.expiresAt) {
		return nil, errTokenExpired
	}
	return rec.scopes, nil
}

// Revoke invalidates a token. Revoking a refresh token ends its whole
// family; revoking an access token ends only that token. Unknown tokens are
// ignored, as RFC 7009 requires.
func (s *TokenStore) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(token)
	if rec := s.refresh[h]; rec != nil {
		s.revoked[rec.family] = true
		return
	}
	delete(s.access, h)
}

// AddStaticToken registers a non-expiring access token, used for local
// development and for clients that skip the login flow.
func (s *TokenStore) AddStaticToken(token string, scopes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.access[hashToken(token)] = &accessRecord{family: "static", scopes: slices.Clone(scopes)}
}

func (s *TokenStore) sweepLocked() {
	now := s.now()
	for h, rec := range s.access {
		if !rec.expiresAt.IsZero() && !now.Before(rec.expiresAt) {
			delete(s.access, h)
		}
	}
	for h, rec := range s.refresh {
		if !now.Before(rec.expiresAt) {
			delete(s.refresh, h)
		}
	}
}
