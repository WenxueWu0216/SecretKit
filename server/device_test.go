package server

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var testVerifier = strings.Repeat("v", 64)

func startFlow(t *testing.T) (*DeviceFlow, *fakeClock, DeviceAuthorization) {
	t.Helper()
	clock := newFakeClock()
	f := NewDeviceFlow(clock.Now, 10*time.Minute, 5*time.Second)
	auth, err := f.Start("cli", []string{ScopeRead}, S256Challenge(testVerifier))
	if err != nil {
		t.Fatal(err)
	}
	return f, clock, auth
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func TestDeviceFlowApprove(t *testing.T) {
	f, clock, auth := startFlow(t)

	_, err := f.Redeem("cli", auth.DeviceCode, testVerifier)
	wantCode(t, err, CodeAuthorizationPending)

	if err := f.Decide(strings.ToLower(strings.ReplaceAll(auth.UserCode, "-", "")), true); err != nil {
		t.Fatalf("Decide with normalized code: %v", err)
	}
	clock.Advance(5 * time.Second)
	scopes, err := f.Redeem("cli", auth.DeviceCode, testVerifier)
	if err != nil {
		t.Fatalf("Redeem after approval: %v", err)
	}
	if len(scopes) != 1 || scopes[0] != ScopeRead {
		t.Fatalf("scopes = %v", scopes)
	}

	clock.Advance(5 * time.Second)
	_, err = f.Redeem("cli", auth.DeviceCode, testVerifier)
	wantCode(t, err, CodeInvalidGrant)
}

func TestDeviceFlowSlowDown(t *testing.T) {
	f, clock, auth := startFlow(t)

	_, err := f.Redeem("cli", auth.DeviceCode, testVerifier)
	wantCode(t, err, CodeAuthorizationPending)

	clock.Advance(time.Second)
	_, err = f.Redeem("cli", auth.DeviceCode, testVerifier)
	wantCode(t, err, CodeSlowDown)
	if iv, _ := f.Interval(auth.DeviceCode); iv != 10*time.Second {
		t.Fatalf("interval after slow_down = %v, want 10s", iv)
	}

	// Waiting the old interval is no longer enough.
	clock.Advance(5 * time.Second)
	_, err = f.Redeem("cli", auth.DeviceCode, testVerifier)
	wantCode(t, err, CodeSlowDown)

	clock.Advance(15 * time.Second)
	_, err = f.Redeem("cli", auth.DeviceCode, testVerifier)
	wantCode(t, err, CodeAuthorizationPending)
}

func TestDeviceFlowDeny(t *testing.T) {
	f, _, auth := startFlow(t)
	if err := f.Decide(auth.UserCode, false); err != nil {
		t.Fatal(err)
	}
	if err := f.Decide(auth.UserCode, true); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("second Decide = %v, want ErrAlreadyDecided", err)
	}
	_, err := f.Redeem("cli", auth.DeviceCode, testVerifier)
	wantCode(t, err, CodeAccessDenied)
}

func TestDeviceFlowExpiry(t *testing.T) {
	f, clock, auth := startFlow(t)
	clock.Advance(10 * time.Minute)
	if err := f.Decide(auth.UserCode, true); !errors.Is(err, ErrUnknownUserCode) {
		t.Fatalf("Decide after expiry = %v", err)
	}
	_, err := f.Redeem("cli", auth.DeviceCode, testVerifier)
	wantCode(t, err, CodeExpiredToken)
}

func TestDeviceFlowWrongVerifierBurnsGrant(t *testing.T) {
	f, clock, auth := startFlow(t)
	if err := f.Decide(auth.UserCode, true); err != nil {
		t.Fatal(err)
	}
	_, err := f.Redeem("cli", auth.DeviceCode, strings.Repeat("w", 64))
	wantCode(t, err, CodeInvalidGrant)

	clock.Advance(5 * time.Second)
	_, err = f.Redeem("cli", auth.DeviceCode, testVerifier)
	wantCode(t, err, CodeInvalidGrant)
}

func TestDeviceFlowWrongClient(t *testing.T) {
	f, _, auth := startFlow(t)
	_, err := f.Redeem("other", auth.DeviceCode, testVerifier)
	wantCode(t, err, CodeInvalidGrant)
}

func TestDeviceFlowStartValidation(t *testing.T) {
	f := NewDeviceFlow(time.Now, time.Minute, time.Second)
	_, err := f.Start("", nil, S256Challenge(testVerifier))
	wantCode(t, err, CodeInvalidClient)
	_, err = f.Start("cli", nil, "not-a-challenge")
	wantCode(t, err, CodeInvalidRequest)
}

func TestUserCodeFormat(t *testing.T) {
	for range 100 {
		code := randomUserCode()
		if len(code) != 9 || code[4] != '-' {
			t.Fatalf("bad user code %q", code)
		}
		if normalizeUserCode(strings.ToLower(code)) != code {
			t.Fatalf("normalize(%q) round trip failed", code)
		}
	}
}
