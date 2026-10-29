package secretkit

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/WenxueWu0216/SecretKit/server"
)

func TestDeviceFlowAgainstServer(t *testing.T) {
	env := newTestEnv(t, server.Config{PollInterval: 5 * time.Second})
	ctx := context.Background()

	da, err := env.client.StartDeviceAuth(ctx, "secretkit-cli", "secrets:read secrets:write")
	if err != nil {
		t.Fatal(err)
	}
	if da.Interval != 5*time.Second || da.UserCode == "" {
		t.Fatalf("device auth = %+v", da)
	}
	// Approve after the second poll so the client sees authorization_pending first.
	env.onSleep = func(n int) {
		if n == 2 {
			if err := env.client.ApproveDevice(ctx, da.UserCode, true); err != nil {
				t.Error(err)
			}
		}
	}
	tok, err := env.client.PollToken(ctx, da)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.sleeps) != 2 || tok.Scope != "secrets:read secrets:write" || tok.RefreshToken == "" {
		t.Fatalf("sleeps=%v token=%+v", env.sleeps, tok)
	}

	env.client.tokens = StaticToken(tok.AccessToken)
	if _, err := env.client.PutSecret(ctx, "API_KEY", "fake-api-key"); err != nil {
		t.Fatal(err)
	}
	sec, err := env.client.GetSecret(ctx, "API_KEY")
	if err != nil || sec.Value != "fake-api-key" || sec.Version != 1 {
		t.Fatalf("GetSecret = %+v, %v", sec, err)
	}
	list, err := env.client.ListSecrets(ctx)
	if err != nil || len(list) != 1 || list[0].Name != "API_KEY" {
		t.Fatalf("ListSecrets = %+v, %v", list, err)
	}
	_, err = env.client.GetSecret(ctx, "MISSING")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "not_found" || !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing secret err = %v", err)
	}
}

func TestDeviceFlowDenied(t *testing.T) {
	env := newTestEnv(t, server.Config{PollInterval: time.Second})
	ctx := context.Background()
	da, err := env.client.StartDeviceAuth(ctx, "cli", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := env.client.ApproveDevice(ctx, da.UserCode, false); err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.PollToken(ctx, da); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("err = %v, want ErrAccessDenied", err)
	}
}

func TestDeviceFlowExpires(t *testing.T) {
	env := newTestEnv(t, server.Config{PollInterval: 5 * time.Second, DeviceCodeTTL: 12 * time.Second})
	ctx := context.Background()
	da, err := env.client.StartDeviceAuth(ctx, "cli", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.PollToken(ctx, da); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("err = %v, want ErrExpiredToken", err)
	}
}

func TestPollTokenSlowDown(t *testing.T) {
	var polls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oauth/device/code" {
			_, _ = io.WriteString(w, `{"device_code":"d","user_code":"BBBB-CCCC","verification_uri":"http://x/device","expires_in":600,"interval":2}`)
			return
		}
		polls++
		if polls == 1 {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"error":"slow_down"}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"a","token_type":"Bearer","expires_in":60,"refresh_token":"r","scope":"secrets:read"}`)
	}))
	defer ts.Close()

	c, _ := New(ts.URL)
	var sleeps []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }
	da, err := c.StartDeviceAuth(context.Background(), "cli", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PollToken(context.Background(), da); err != nil {
		t.Fatal(err)
	}
	if len(sleeps) != 2 || sleeps[0] != 2*time.Second || sleeps[1] != 7*time.Second {
		t.Fatalf("sleeps = %v, want [2s 7s]", sleeps)
	}
}

func TestPollTokenCancel(t *testing.T) {
	env := newTestEnv(t, server.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	da, err := env.client.StartDeviceAuth(ctx, "cli", "")
	if err != nil {
		t.Fatal(err)
	}
	env.onSleep = func(int) { cancel() }
	if _, err := env.client.PollToken(ctx, da); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func loginForTest(t *testing.T, env *testEnv, scope string) Token {
	t.Helper()
	ctx := context.Background()
	da, err := env.client.StartDeviceAuth(ctx, "cli", scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.client.ApproveDevice(ctx, da.UserCode, true); err != nil {
		t.Fatal(err)
	}
	tok, err := env.client.PollToken(ctx, da)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRefreshingTokenSourceRefreshesExpiredToken(t *testing.T) {
	env := newTestEnv(t, server.Config{AccessTokenTTL: time.Minute, PollInterval: time.Second})
	tok := loginForTest(t, env, "secrets:read")
	ts := env.client.NewRefreshingTokenSource("cli", tok)
	var persisted []Token
	ts.OnRefresh = func(t Token) error { persisted = append(persisted, t); return nil }
	env.client.tokens = ts

	env.clock.Advance(2 * time.Minute)
	if _, err := env.client.ListSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 1 || persisted[0].RefreshToken == tok.RefreshToken {
		t.Fatalf("refresh not persisted/rotated: %+v", persisted)
	}
	if ts.Current().AccessToken != persisted[0].AccessToken {
		t.Fatal("Current() is stale")
	}
}

func TestRefreshingTokenSourceRecoversFrom401(t *testing.T) {
	env := newTestEnv(t, server.Config{PollInterval: time.Second})
	tok := loginForTest(t, env, "secrets:read")
	// The server forgets this access token while the client still thinks it
	// is valid, as happens after a server-side revocation of one token.
	env.srv.Tokens.Revoke(tok.AccessToken)

	ts := env.client.NewRefreshingTokenSource("cli", tok)
	env.client.tokens = ts
	if _, err := env.client.ListSecrets(context.Background()); err != nil {
		t.Fatalf("expected transparent refresh, got %v", err)
	}
	if ts.Current().AccessToken == tok.AccessToken {
		t.Fatal("token was not refreshed")
	}
}

func TestRefreshFailureSurfacesInvalidGrant(t *testing.T) {
	env := newTestEnv(t, server.Config{AccessTokenTTL: time.Minute, PollInterval: time.Second})
	tok := loginForTest(t, env, "secrets:read")
	env.srv.Tokens.Revoke(tok.RefreshToken)
	env.client.tokens = env.client.NewRefreshingTokenSource("cli", tok)
	env.clock.Advance(2 * time.Minute)
	if _, err := env.client.ListSecrets(context.Background()); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("err = %v, want ErrInvalidGrant", err)
	}
}

func TestScopeEnforcedThroughSDK(t *testing.T) {
	env := newTestEnv(t, server.Config{PollInterval: time.Second})
	tok := loginForTest(t, env, "secrets:read")
	env.client.tokens = StaticToken(tok.AccessToken)
	if _, err := env.client.PutSecret(context.Background(), "A", "fake"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestNoTokenSource(t *testing.T) {
	c, _ := New("http://127.0.0.1:1")
	if _, err := c.ListSecrets(context.Background()); !errors.Is(err, errNoTokenSource) {
		t.Fatalf("err = %v", err)
	}
}
