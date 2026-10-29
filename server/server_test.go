package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
)

// specHarness sends requests to a live server and checks that both the
// request and the response conform to openapi/secretkit.yaml.
type specHarness struct {
	t      *testing.T
	srv    *Server
	clock  *fakeClock
	url    string
	router routers.Router
}

func newSpecHarness(t *testing.T, cfg Config) *specHarness {
	t.Helper()
	clock := newFakeClock()
	cfg.Now = clock.Now
	srv := New(cfg)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	doc, err := openapi3.NewLoader().LoadFromFile("../openapi/secretkit.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("spec is invalid: %v", err)
	}
	doc.Servers = openapi3.Servers{{URL: ts.URL}}
	router, err := legacy.NewRouter(doc)
	if err != nil {
		t.Fatal(err)
	}
	return &specHarness{t: t, srv: srv, clock: clock, url: ts.URL, router: router}
}

type response struct {
	status int
	header http.Header
	body   map[string]any
}

func (h *specHarness) do(method, path, token, contentType string, body []byte) response {
	h.t.Helper()
	req, err := http.NewRequest(method, h.url+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	route, params, err := h.router.FindRoute(req)
	if err != nil {
		h.t.Fatalf("%s %s is not in the spec: %v", method, path, err)
	}
	reqInput := &openapi3filter.RequestValidationInput{
		Request: req, PathParams: params, Route: route,
		Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
	}
	// Invalid requests are sent on purpose in some tests, so request
	// validation failures are not fatal; the response must still conform.
	_ = openapi3filter.ValidateRequest(context.Background(), reqInput)
	req.Body = io.NopCloser(bytes.NewReader(body))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)

	respInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: reqInput,
		Status:                 resp.StatusCode,
		Header:                 resp.Header,
		Options:                &openapi3filter.Options{IncludeResponseStatus: true},
	}
	respInput.SetBodyBytes(raw)
	if err := openapi3filter.ValidateResponse(context.Background(), respInput); err != nil {
		h.t.Errorf("%s %s -> %d does not match spec: %v\nbody: %s", method, path, resp.StatusCode, err, raw)
	}

	out := response{status: resp.StatusCode, header: resp.Header}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out.body)
	}
	return out
}

func (h *specHarness) form(path string, values url.Values) response {
	h.t.Helper()
	return h.do(http.MethodPost, path, "", "application/x-www-form-urlencoded", []byte(values.Encode()))
}

func (h *specHarness) putSecret(token, name, value string) response {
	h.t.Helper()
	body, _ := json.Marshal(map[string]string{"value": value})
	return h.do(http.MethodPut, "/v1/secrets/"+name, token, "application/json", body)
}

func expectError(t *testing.T, r response, status int, code string) {
	t.Helper()
	if r.status != status || r.body["error"] != code {
		t.Fatalf("got %d %v, want %d %s", r.status, r.body, status, code)
	}
}

// login runs the device flow over HTTP and returns the token response.
func (h *specHarness) login(scope string) map[string]any {
	h.t.Helper()
	verifier := strings.Repeat("k", 50)
	start := h.form("/oauth/device/code", url.Values{
		"client_id": {"secretkit-cli"}, "scope": {scope},
		"code_challenge": {S256Challenge(verifier)}, "code_challenge_method": {"S256"},
	})
	if start.status != http.StatusOK {
		h.t.Fatalf("device code: %d %v", start.status, start.body)
	}
	poll := url.Values{
		"grant_type": {grantTypeDeviceCode}, "client_id": {"secretkit-cli"},
		"device_code": {start.body["device_code"].(string)}, "code_verifier": {verifier},
	}
	expectError(h.t, h.form("/oauth/token", poll), http.StatusBadRequest, CodeAuthorizationPending)

	r := h.form("/oauth/device/verify", url.Values{"user_code": {start.body["user_code"].(string)}, "action": {"approve"}})
	if r.status != http.StatusNoContent {
		h.t.Fatalf("verify: %d %v", r.status, r.body)
	}
	h.clock.Advance(5 * time.Second)
	tok := h.form("/oauth/token", poll)
	if tok.status != http.StatusOK {
		h.t.Fatalf("token: %d %v", tok.status, tok.body)
	}
	if tok.header.Get("Cache-Control") != "no-store" {
		h.t.Error("token response is cacheable")
	}
	return tok.body
}

func TestHTTPDeviceLoginAndSecrets(t *testing.T) {
	h := newSpecHarness(t, Config{BaseURL: "http://example.test"})
	tok := h.login("secrets:read secrets:write")
	access := tok["access_token"].(string)
	if tok["scope"] != "secrets:read secrets:write" {
		t.Fatalf("scope = %v", tok["scope"])
	}

	r := h.putSecret(access, "DB_PASSWORD", "fake-db-password")
	if r.status != http.StatusOK || r.body["version"] != 1.0 {
		t.Fatalf("put: %d %v", r.status, r.body)
	}
	r = h.putSecret(access, "DB_PASSWORD", "fake-db-password-2")
	if r.body["version"] != 2.0 {
		t.Fatalf("second put version = %v", r.body["version"])
	}

	r = h.do(http.MethodGet, "/v1/secrets/DB_PASSWORD", access, "", nil)
	if r.status != http.StatusOK || r.body["value"] != "fake-db-password-2" {
		t.Fatalf("get: %d %v", r.status, r.body)
	}

	r = h.do(http.MethodGet, "/v1/secrets", access, "", nil)
	list := r.body["secrets"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["value"] != nil {
		t.Fatalf("list leaked values or wrong length: %v", r.body)
	}

	expectError(t, h.do(http.MethodGet, "/v1/secrets/MISSING", access, "", nil), http.StatusNotFound, CodeNotFound)
}

func TestHTTPAuthErrors(t *testing.T) {
	h := newSpecHarness(t, Config{})
	h.srv.Tokens.AddStaticToken("fake-read-only", []string{ScopeRead})

	r := h.do(http.MethodGet, "/v1/secrets", "", "", nil)
	expectError(t, r, http.StatusUnauthorized, CodeInvalidToken)
	if r.header.Get("WWW-Authenticate") == "" {
		t.Error("401 without WWW-Authenticate")
	}
	expectError(t, h.do(http.MethodGet, "/v1/secrets", "nope", "", nil), http.StatusUnauthorized, CodeInvalidToken)

	r = h.putSecret("fake-read-only", "X", "y")
	expectError(t, r, http.StatusForbidden, CodeInsufficientScope)
	if !strings.Contains(r.header.Get("WWW-Authenticate"), `scope="secrets:write"`) {
		t.Errorf("WWW-Authenticate = %q", r.header.Get("WWW-Authenticate"))
	}
}

func TestHTTPAccessTokenExpiryAndRefresh(t *testing.T) {
	h := newSpecHarness(t, Config{AccessTokenTTL: time.Minute})
	tok := h.login("secrets:read")
	h.clock.Advance(time.Minute)
	expectError(t, h.do(http.MethodGet, "/v1/secrets", tok["access_token"].(string), "", nil),
		http.StatusUnauthorized, CodeInvalidToken)

	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {"secretkit-cli"},
		"refresh_token": {tok["refresh_token"].(string)}}
	r := h.form("/oauth/token", refresh)
	if r.status != http.StatusOK {
		t.Fatalf("refresh: %d %v", r.status, r.body)
	}
	if got := h.do(http.MethodGet, "/v1/secrets", r.body["access_token"].(string), "", nil); got.status != http.StatusOK {
		t.Fatalf("refreshed token rejected: %d", got.status)
	}
	expectError(t, h.form("/oauth/token", refresh), http.StatusBadRequest, CodeInvalidGrant)
}

func TestHTTPRevoke(t *testing.T) {
	h := newSpecHarness(t, Config{})
	tok := h.login("secrets:read")
	r := h.form("/oauth/revoke", url.Values{"token": {tok["refresh_token"].(string)}})
	if r.status != http.StatusOK {
		t.Fatalf("revoke: %d", r.status)
	}
	expectError(t, h.do(http.MethodGet, "/v1/secrets", tok["access_token"].(string), "", nil),
		http.StatusUnauthorized, CodeInvalidToken)
}

func TestHTTPDeviceDenied(t *testing.T) {
	h := newSpecHarness(t, Config{})
	verifier := strings.Repeat("d", 43)
	start := h.form("/oauth/device/code", url.Values{"client_id": {"c"},
		"code_challenge": {S256Challenge(verifier)}, "code_challenge_method": {"S256"}})
	h.form("/oauth/device/verify", url.Values{"user_code": {start.body["user_code"].(string)}, "action": {"deny"}})
	r := h.form("/oauth/token", url.Values{"grant_type": {grantTypeDeviceCode}, "client_id": {"c"},
		"device_code": {start.body["device_code"].(string)}, "code_verifier": {verifier}})
	expectError(t, r, http.StatusBadRequest, CodeAccessDenied)

	expectError(t, h.form("/oauth/device/verify", url.Values{"user_code": {"BBBB-BBBB"}, "action": {"approve"}}),
		http.StatusNotFound, CodeNotFound)
}

func TestHTTPValidation(t *testing.T) {
	h := newSpecHarness(t, Config{})
	h.srv.Tokens.AddStaticToken("fake-admin", []string{ScopeRead, ScopeWrite})

	expectError(t, h.form("/oauth/device/code", url.Values{"client_id": {"c"}, "code_challenge": {"x"},
		"code_challenge_method": {"plain"}}), http.StatusBadRequest, CodeInvalidRequest)
	expectError(t, h.form("/oauth/device/code", url.Values{"client_id": {"c"}, "scope": {"admin"},
		"code_challenge": {S256Challenge(strings.Repeat("a", 43))}, "code_challenge_method": {"S256"}}),
		http.StatusBadRequest, CodeInvalidScope)
	expectError(t, h.form("/oauth/token", url.Values{"client_id": {"c"}, "grant_type": {"password"}}),
		http.StatusBadRequest, CodeUnsupportedGrantType)

	expectError(t, h.putSecret("fake-admin", "1BAD", "v"), http.StatusBadRequest, CodeInvalidRequest)
	expectError(t, h.putSecret("fake-admin", "BIG", strings.Repeat("x", MaxSecretSize+1)), http.StatusBadRequest, CodeInvalidRequest)
	expectError(t, h.do(http.MethodPut, "/v1/secrets/X", "fake-admin", "application/json", []byte(`{"val":1}`)),
		http.StatusBadRequest, CodeInvalidRequest)
}

func TestHTTPRateLimit(t *testing.T) {
	h := newSpecHarness(t, Config{RateLimit: 2})
	h.srv.Tokens.AddStaticToken("fake-token", []string{ScopeRead})
	for i := range 2 {
		if r := h.do(http.MethodGet, "/v1/secrets", "fake-token", "", nil); r.status != http.StatusOK {
			t.Fatalf("request %d: %d", i, r.status)
		}
	}
	r := h.do(http.MethodGet, "/v1/secrets", "fake-token", "", nil)
	expectError(t, r, http.StatusTooManyRequests, CodeRateLimited)
	if r.header.Get("Retry-After") != "1" {
		t.Errorf("Retry-After = %q", r.header.Get("Retry-After"))
	}
	h.clock.Advance(time.Second)
	if r := h.do(http.MethodGet, "/v1/secrets", "fake-token", "", nil); r.status != http.StatusOK {
		t.Fatalf("after refill: %d", r.status)
	}
}
