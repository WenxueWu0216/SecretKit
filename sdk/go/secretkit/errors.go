package secretkit

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/WenxueWu0216/SecretKit/sdk/go/api"
)

// Sentinel errors for use with errors.Is.
var (
	ErrUnauthorized         = errors.New("secretkit: unauthorized")
	ErrForbidden            = errors.New("secretkit: forbidden")
	ErrNotFound             = errors.New("secretkit: not found")
	ErrRateLimited          = errors.New("secretkit: rate limited")
	ErrServer               = errors.New("secretkit: server error")
	ErrInvalidRequest       = errors.New("secretkit: invalid request")
	ErrAuthorizationPending = errors.New("secretkit: authorization pending")
	ErrSlowDown             = errors.New("secretkit: slow down")
	ErrAccessDenied         = errors.New("secretkit: access denied")
	ErrExpiredToken         = errors.New("secretkit: device code expired")
	ErrInvalidGrant         = errors.New("secretkit: invalid grant")
)

// APIError is returned for every non-2xx response.
type APIError struct {
	StatusCode  int
	Code        string
	Description string
	// RetryAfter is set when the server sent a Retry-After header.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("secretkit: %d %s", e.StatusCode, e.Code)
	if e.Description != "" {
		msg += ": " + e.Description
	}
	return msg
}

// Is maps the error onto the sentinel errors. OAuth codes take precedence
// over HTTP status because the token endpoint reports everything as 400.
func (e *APIError) Is(target error) bool {
	if s, ok := codeSentinels[e.Code]; ok && s == target {
		return true
	}
	return statusSentinel(e.StatusCode) == target
}

var codeSentinels = map[string]error{
	"authorization_pending": ErrAuthorizationPending,
	"slow_down":             ErrSlowDown,
	"access_denied":         ErrAccessDenied,
	"expired_token":         ErrExpiredToken,
	"invalid_grant":         ErrInvalidGrant,
	"invalid_token":         ErrUnauthorized,
	"insufficient_scope":    ErrForbidden,
	"not_found":             ErrNotFound,
	"rate_limited":          ErrRateLimited,
	"invalid_request":       ErrInvalidRequest,
}

func statusSentinel(status int) error {
	switch {
	case status == http.StatusUnauthorized:
		return ErrUnauthorized
	case status == http.StatusForbidden:
		return ErrForbidden
	case status == http.StatusNotFound:
		return ErrNotFound
	case status == http.StatusTooManyRequests:
		return ErrRateLimited
	case status >= 500:
		return ErrServer
	case status == http.StatusBadRequest:
		return ErrInvalidRequest
	}
	return nil
}

// newAPIError builds an APIError from whichever typed error body the
// generated client decoded, falling back to the status code.
func newAPIError(resp *http.Response, bodies ...*api.Error) *APIError {
	e := &APIError{StatusCode: resp.StatusCode, Code: http.StatusText(resp.StatusCode)}
	for _, b := range bodies {
		if b == nil {
			continue
		}
		e.Code = string(b.Error)
		if b.ErrorDescription != nil {
			e.Description = *b.ErrorDescription
		}
		break
	}
	if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs >= 0 {
		e.RetryAfter = time.Duration(secs) * time.Second
	}
	return e
}
