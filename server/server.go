// Package server is an in-memory mock of the SecretKit API described in
// openapi/secretkit.yaml.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	grantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	grantTypeRefresh    = "refresh_token"
	maxFormBytes        = 16 * 1024
	maxJSONBytes        = MaxSecretSize + 1024
)

// Config controls token lifetimes and limits. Zero values get defaults.
type Config struct {
	// BaseURL is used to build verification_uri.
	BaseURL         string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	DeviceCodeTTL   time.Duration
	PollInterval    time.Duration
	// RateLimit is requests per second per caller; 0 disables limiting.
	RateLimit float64
	Now       func() time.Time
	Logger    *slog.Logger
}

func (c *Config) setDefaults() {
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = 15 * time.Minute
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = 24 * time.Hour
	}
	if c.DeviceCodeTTL == 0 {
		c.DeviceCodeTTL = 10 * time.Minute
	}
	if c.PollInterval == 0 {
		c.PollInterval = 5 * time.Second
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Server wires the stores to HTTP handlers.
type Server struct {
	cfg     Config
	Devices *DeviceFlow
	Tokens  *TokenStore
	Secrets *SecretStore
	limiter *rateLimiter
	mux     *http.ServeMux
}

func New(cfg Config) *Server {
	cfg.setDefaults()
	s := &Server{
		cfg:     cfg,
		Devices: NewDeviceFlow(cfg.Now, cfg.DeviceCodeTTL, cfg.PollInterval),
		Tokens:  NewTokenStore(cfg.Now, cfg.AccessTokenTTL, cfg.RefreshTokenTTL),
		Secrets: NewSecretStore(cfg.Now),
		mux:     http.NewServeMux(),
	}
	if cfg.RateLimit > 0 {
		s.limiter = newRateLimiter(cfg.Now, cfg.RateLimit, int(cfg.RateLimit))
	}
	s.mux.HandleFunc("POST /oauth/device/code", s.handleDeviceCode)
	s.mux.HandleFunc("POST /oauth/device/verify", s.handleDeviceVerify)
	s.mux.HandleFunc("POST /oauth/token", s.handleToken)
	s.mux.HandleFunc("POST /oauth/revoke", s.handleRevoke)
	s.mux.HandleFunc("GET /v1/secrets", s.requireScope(ScopeRead, s.handleListSecrets))
	s.mux.HandleFunc("GET /v1/secrets/{name}", s.requireScope(ScopeRead, s.handleGetSecret))
	s.mux.HandleFunc("PUT /v1/secrets/{name}", s.requireScope(ScopeWrite, s.handlePutSecret))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := s.cfg.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	if s.limiter != nil && !s.limiter.allow(rateKey(r)) {
		rec.Header().Set("Retry-After", "1")
		writeError(rec, http.StatusTooManyRequests, CodeRateLimited, "rate limit exceeded")
	} else {
		s.mux.ServeHTTP(rec, r)
	}
	// Only method, path and status are logged: never headers or bodies,
	// which carry tokens and secret values.
	s.cfg.Logger.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
		"duration", s.cfg.Now().Sub(start).String())
}

func rateKey(r *http.Request) string {
	if tok, ok := bearerToken(r); ok {
		return "tok:" + hashToken(tok)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "ip:" + host
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (s *Server) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	if m := r.PostForm.Get("code_challenge_method"); m != "S256" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "code_challenge_method must be S256")
		return
	}
	scopes, err := parseScopes(r.PostForm.Get("scope"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	auth, err := s.Devices.Start(r.PostForm.Get("client_id"), scopes, r.PostForm.Get("code_challenge"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	verifyURI := strings.TrimRight(s.cfg.BaseURL, "/") + "/device"
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               auth.DeviceCode,
		"user_code":                 auth.UserCode,
		"verification_uri":          verifyURI,
		"verification_uri_complete": verifyURI + "?user_code=" + auth.UserCode,
		"expires_in":                int(auth.ExpiresIn.Seconds()),
		"interval":                  int(auth.Interval.Seconds()),
	})
}

func (s *Server) handleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	var approve bool
	switch r.PostForm.Get("action") {
	case "approve":
		approve = true
	case "deny":
	default:
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "action must be approve or deny")
		return
	}
	switch err := s.Devices.Decide(r.PostForm.Get("user_code"), approve); {
	case errors.Is(err, ErrUnknownUserCode):
		writeError(w, http.StatusNotFound, CodeNotFound, err.Error())
	case errors.Is(err, ErrAlreadyDecided):
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, CodeServerError, "")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	clientID := r.PostForm.Get("client_id")
	if clientID == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidClient, "client_id is required")
		return
	}
	var pair TokenPair
	switch r.PostForm.Get("grant_type") {
	case grantTypeDeviceCode:
		scopes, err := s.Devices.Redeem(clientID, r.PostForm.Get("device_code"), r.PostForm.Get("code_verifier"))
		if err != nil {
			writeOAuthError(w, err)
			return
		}
		pair = s.Tokens.Issue(clientID, scopes)
	case grantTypeRefresh:
		var err error
		pair, err = s.Tokens.Refresh(clientID, r.PostForm.Get("refresh_token"))
		if err != nil {
			writeOAuthError(w, err)
			return
		}
	default:
		writeError(w, http.StatusBadRequest, CodeUnsupportedGrantType, "")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  pair.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    int(pair.ExpiresIn.Seconds()),
		"refresh_token": pair.RefreshToken,
		"scope":         strings.Join(pair.Scopes, " "),
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "token is required")
		return
	}
	s.Tokens.Revoke(token)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"secrets": s.Secrets.List()})
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !ValidSecretName(name) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid secret name")
		return
	}
	sec, ok := s.Secrets.Get(name)
	if !ok {
		writeError(w, http.StatusNotFound, CodeNotFound, "secret "+name+" not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, sec)
}

func (s *Server) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !ValidSecretName(name) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid secret name")
		return
	}
	var body struct {
		Value *string `json:"value"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.Value == nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "body must be {\"value\": string}")
		return
	}
	if len(*body.Value) > MaxSecretSize {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "value exceeds "+strconv.Itoa(MaxSecretSize)+" bytes")
		return
	}
	writeJSON(w, http.StatusOK, s.Secrets.Put(name, *body.Value))
}

func (s *Server) requireScope(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="secretkit"`)
			writeError(w, http.StatusUnauthorized, CodeInvalidToken, "missing bearer token")
			return
		}
		scopes, err := s.Tokens.Authenticate(token)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="secretkit", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, CodeInvalidToken, err.Error())
			return
		}
		if !slices.Contains(scopes, scope) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="secretkit", error="insufficient_scope", scope="`+scope+`"`)
			writeError(w, http.StatusForbidden, CodeInsufficientScope, "requires scope "+scope)
			return
		}
		next(w, r)
	}
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

func parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "malformed form body")
		return false
	}
	return true
}

func writeOAuthError(w http.ResponseWriter, err error) {
	var oe *OAuthError
	if !errors.As(err, &oe) {
		writeError(w, http.StatusInternalServerError, CodeServerError, "")
		return
	}
	// The spec declares only 400 for OAuth endpoint errors, including
	// invalid_client, so mock clients never need to special-case 401 here.
	writeError(w, http.StatusBadRequest, oe.Code, oe.Description)
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
