package secretkit

import (
	"errors"
	"testing"
)

func TestAPIErrorIs(t *testing.T) {
	tests := []struct {
		status int
		code   string
		want   error
	}{
		{401, "invalid_token", ErrUnauthorized},
		{403, "insufficient_scope", ErrForbidden},
		{404, "not_found", ErrNotFound},
		{429, "rate_limited", ErrRateLimited},
		{500, "server_error", ErrServer},
		{502, "Bad Gateway", ErrServer},
		{400, "authorization_pending", ErrAuthorizationPending},
		{400, "slow_down", ErrSlowDown},
		{400, "access_denied", ErrAccessDenied},
		{400, "expired_token", ErrExpiredToken},
		{400, "invalid_grant", ErrInvalidGrant},
		{400, "invalid_request", ErrInvalidRequest},
	}
	for _, tt := range tests {
		err := error(&APIError{StatusCode: tt.status, Code: tt.code})
		if !errors.Is(err, tt.want) {
			t.Errorf("%d %s: errors.Is(%v) = false", tt.status, tt.code, tt.want)
		}
	}

	pending := &APIError{StatusCode: 400, Code: "authorization_pending"}
	if errors.Is(pending, ErrAccessDenied) {
		t.Error("authorization_pending matched ErrAccessDenied")
	}
	// Status mapping still applies alongside the code mapping.
	if !errors.Is(pending, ErrInvalidRequest) {
		t.Error("400 did not match ErrInvalidRequest")
	}
}

func TestAPIErrorMessageOmitsNothingSensitive(t *testing.T) {
	err := &APIError{StatusCode: 404, Code: "not_found", Description: "secret DB not found"}
	if got, want := err.Error(), "secretkit: 404 not_found: secret DB not found"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}
