package server

import "fmt"

// OAuthError carries an error code from the spec's Error schema.
type OAuthError struct {
	Code        string
	Description string
}

func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func oauthErr(code, desc string) *OAuthError { return &OAuthError{Code: code, Description: desc} }

// Error codes shared by the OAuth and secrets endpoints.
const (
	CodeInvalidRequest       = "invalid_request"
	CodeInvalidClient        = "invalid_client"
	CodeInvalidGrant         = "invalid_grant"
	CodeInvalidScope         = "invalid_scope"
	CodeUnsupportedGrantType = "unsupported_grant_type"
	CodeAuthorizationPending = "authorization_pending"
	CodeSlowDown             = "slow_down"
	CodeAccessDenied         = "access_denied"
	CodeExpiredToken         = "expired_token"
	CodeInvalidToken         = "invalid_token"
	CodeInsufficientScope    = "insufficient_scope"
	CodeNotFound             = "not_found"
	CodeRateLimited          = "rate_limited"
	CodeServerError          = "server_error"
)
