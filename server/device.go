package server

import (
	"errors"
	"sync"
	"time"
)

// DeviceState is the lifecycle of a device authorization request.
//
//	pending --approve--> approved --redeem--> (removed)
//	pending --deny-----> denied   --poll----> (removed)
//	any     --expiry---> (removed on next poll)
type DeviceState int

const (
	DevicePending DeviceState = iota
	DeviceApproved
	DeviceDenied
)

// slowDownStep is the interval increase mandated by RFC 8628 section 3.5.
const slowDownStep = 5 * time.Second

var (
	ErrUnknownUserCode = errors.New("unknown or expired user code")
	ErrAlreadyDecided  = errors.New("user code already approved or denied")
)

type deviceGrant struct {
	deviceHash string
	userCode   string
	clientID   string
	scopes     []string
	challenge  string
	expiresAt  time.Time
	interval   time.Duration
	lastPoll   time.Time
	state      DeviceState
}

// DeviceAuthorization is what the client needs to show the user and poll.
type DeviceAuthorization struct {
	DeviceCode string
	UserCode   string
	ExpiresIn  time.Duration
	Interval   time.Duration
}

// DeviceFlow implements the server side of RFC 8628 with a PKCE binding.
type DeviceFlow struct {
	mu       sync.Mutex
	now      func() time.Time
	ttl      time.Duration
	interval time.Duration
	byDevice map[string]*deviceGrant
	byUser   map[string]*deviceGrant
}

func NewDeviceFlow(now func() time.Time, ttl, interval time.Duration) *DeviceFlow {
	return &DeviceFlow{
		now:      now,
		ttl:      ttl,
		interval: interval,
		byDevice: make(map[string]*deviceGrant),
		byUser:   make(map[string]*deviceGrant),
	}
}

// Start registers a new pending request.
func (f *DeviceFlow) Start(clientID string, scopes []string, challenge string) (DeviceAuthorization, error) {
	if clientID == "" {
		return DeviceAuthorization{}, oauthErr(CodeInvalidClient, "client_id is required")
	}
	if !validChallenge(challenge) {
		return DeviceAuthorization{}, oauthErr(CodeInvalidRequest, "code_challenge must be an unpadded base64url SHA-256 digest")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked()

	deviceCode := randomToken(32)
	userCode := randomUserCode()
	for f.byUser[userCode] != nil {
		userCode = randomUserCode()
	}
	g := &deviceGrant{
		deviceHash: hashToken(deviceCode),
		userCode:   userCode,
		clientID:   clientID,
		scopes:     scopes,
		challenge:  challenge,
		expiresAt:  f.now().Add(f.ttl),
		interval:   f.interval,
		state:      DevicePending,
	}
	f.byDevice[g.deviceHash] = g
	f.byUser[userCode] = g
	return DeviceAuthorization{DeviceCode: deviceCode, UserCode: userCode, ExpiresIn: f.ttl, Interval: f.interval}, nil
}

// Decide records the user's approval or denial for a pending user code.
func (f *DeviceFlow) Decide(userCode string, approve bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := f.byUser[normalizeUserCode(userCode)]
	if g == nil || !f.now().Before(g.expiresAt) {
		return ErrUnknownUserCode
	}
	if g.state != DevicePending {
		return ErrAlreadyDecided
	}
	if approve {
		g.state = DeviceApproved
	} else {
		g.state = DeviceDenied
	}
	return nil
}

// Redeem is called on every poll. It returns the granted scopes once the
// user has approved and the PKCE verifier matches.
func (f *DeviceFlow) Redeem(clientID, deviceCode, verifier string) ([]string, error) {
	if deviceCode == "" {
		return nil, oauthErr(CodeInvalidRequest, "device_code is required")
	}
	if verifier == "" {
		return nil, oauthErr(CodeInvalidRequest, "code_verifier is required")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	g := f.byDevice[hashToken(deviceCode)]
	if g == nil || g.clientID != clientID {
		return nil, oauthErr(CodeInvalidGrant, "unknown device_code")
	}
	if !now.Before(g.expiresAt) {
		f.removeLocked(g)
		return nil, oauthErr(CodeExpiredToken, "device_code expired")
	}
	if !g.lastPoll.IsZero() && now.Sub(g.lastPoll) < g.interval {
		g.interval += slowDownStep
		g.lastPoll = now
		return nil, oauthErr(CodeSlowDown, "polling too fast")
	}
	g.lastPoll = now

	switch g.state {
	case DevicePending:
		return nil, oauthErr(CodeAuthorizationPending, "")
	case DeviceDenied:
		f.removeLocked(g)
		return nil, oauthErr(CodeAccessDenied, "the user denied the request")
	}

	// The grant is single-use whether or not the verifier matches, so a
	// stolen device_code cannot be used to guess verifiers.
	f.removeLocked(g)
	if !verifyPKCE(g.challenge, verifier) {
		return nil, oauthErr(CodeInvalidGrant, "code_verifier does not match code_challenge")
	}
	return g.scopes, nil
}

// Interval reports the current polling interval for a device code, for tests.
func (f *DeviceFlow) Interval(deviceCode string) (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := f.byDevice[hashToken(deviceCode)]
	if g == nil {
		return 0, false
	}
	return g.interval, true
}

func (f *DeviceFlow) removeLocked(g *deviceGrant) {
	delete(f.byDevice, g.deviceHash)
	delete(f.byUser, g.userCode)
}

func (f *DeviceFlow) sweepLocked() {
	now := f.now()
	for _, g := range f.byDevice {
		if !now.Before(g.expiresAt) {
			f.removeLocked(g)
		}
	}
}
