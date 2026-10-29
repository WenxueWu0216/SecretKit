package server

import (
	"errors"
	"testing"
	"time"
)

func newTestTokens() (*TokenStore, *fakeClock) {
	clock := newFakeClock()
	return NewTokenStore(clock.Now, time.Minute, time.Hour), clock
}

func TestTokenAccessExpiry(t *testing.T) {
	s, clock := newTestTokens()
	pair := s.Issue("cli", []string{ScopeRead})
	if _, err := s.Authenticate(pair.AccessToken); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Minute)
	if _, err := s.Authenticate(pair.AccessToken); !errors.Is(err, errTokenExpired) {
		t.Fatalf("Authenticate after TTL = %v, want errTokenExpired", err)
	}
}

func TestTokenRefreshRotates(t *testing.T) {
	s, clock := newTestTokens()
	first := s.Issue("cli", []string{ScopeRead, ScopeWrite})
	clock.Advance(2 * time.Minute)

	second, err := s.Refresh("cli", first.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if second.RefreshToken == first.RefreshToken || second.AccessToken == first.AccessToken {
		t.Fatal("refresh did not rotate tokens")
	}
	scopes, err := s.Authenticate(second.AccessToken)
	if err != nil || len(scopes) != 2 {
		t.Fatalf("new access token: scopes=%v err=%v", scopes, err)
	}
}

func TestTokenRefreshReuseRevokesFamily(t *testing.T) {
	s, _ := newTestTokens()
	first := s.Issue("cli", []string{ScopeRead})
	second, err := s.Refresh("cli", first.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.Refresh("cli", first.RefreshToken)
	wantCode(t, err, CodeInvalidGrant)

	if _, err := s.Authenticate(second.AccessToken); err == nil {
		t.Fatal("access token survived refresh token reuse")
	}
	_, err = s.Refresh("cli", second.RefreshToken)
	wantCode(t, err, CodeInvalidGrant)
}

func TestTokenRefreshExpired(t *testing.T) {
	s, clock := newTestTokens()
	pair := s.Issue("cli", []string{ScopeRead})
	clock.Advance(time.Hour)
	_, err := s.Refresh("cli", pair.RefreshToken)
	wantCode(t, err, CodeInvalidGrant)
}

func TestTokenRefreshWrongClient(t *testing.T) {
	s, _ := newTestTokens()
	pair := s.Issue("cli", []string{ScopeRead})
	_, err := s.Refresh("other", pair.RefreshToken)
	wantCode(t, err, CodeInvalidGrant)
	// A failed attempt by another client must not burn the token.
	if _, err := s.Refresh("cli", pair.RefreshToken); err != nil {
		t.Fatalf("legitimate refresh failed: %v", err)
	}
}

func TestTokenRevoke(t *testing.T) {
	s, _ := newTestTokens()
	pair := s.Issue("cli", []string{ScopeRead})
	s.Revoke(pair.RefreshToken)
	if _, err := s.Authenticate(pair.AccessToken); err == nil {
		t.Fatal("access token valid after refresh token revoked")
	}
	s.Revoke("unknown-token") // must not panic
}

func TestStaticTokenNeverExpires(t *testing.T) {
	s, clock := newTestTokens()
	s.AddStaticToken("dev-token-for-tests", []string{ScopeRead})
	clock.Advance(1000 * time.Hour)
	if _, err := s.Authenticate("dev-token-for-tests"); err != nil {
		t.Fatal(err)
	}
}
