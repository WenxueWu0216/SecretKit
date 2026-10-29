package cli

import (
	"context"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/WenxueWu0216/SecretKit/sdk/go/secretkit"
	"github.com/WenxueWu0216/SecretKit/server"
	"github.com/zalando/go-keyring"
)

type e2e struct {
	t      *testing.T
	url    string
	srv    *server.Server
	extEnv map[string]string
}

func newE2E(t *testing.T, cfg server.Config) *e2e {
	t.Helper()
	keyring.MockInit()
	cfg.PollInterval = time.Second
	srv := server.New(cfg)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &e2e{t: t, url: ts.URL, srv: srv, extEnv: map[string]string{}}
}

type result struct {
	code           int
	stdout, stderr string
}

// cli runs one secretkit invocation in-process, as a separate process would:
// fresh app state each time, with only the keychain shared between runs.
func (e *e2e) cli(stdin string, stderr *syncBuffer, args ...string) result {
	e.t.Helper()
	if stderr == nil {
		stderr = &syncBuffer{}
	}
	var stdout syncBuffer
	env := Env{
		Stdin:  strings.NewReader(stdin),
		Stdout: &stdout,
		Stderr: stderr,
		Getenv: func(k string) string {
			if k == "SECRETKIT_SERVER" {
				return e.url
			}
			return e.extEnv[k]
		},
		Environ: func() []string { return []string{"PATH=" + os.Getenv("PATH")} },
		Tokens:  KeyringStore{},
		Version: "test",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code := Execute(ctx, env, args)
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

var userCodeRE = regexp.MustCompile(`code: ([B-Z]{4}-[B-Z]{4})`)

// login runs `secretkit login` and approves the code as soon as it is printed.
func (e *e2e) login(scope string) {
	e.t.Helper()
	var stderr syncBuffer
	approver, err := secretkit.New(e.url)
	if err != nil {
		e.t.Fatal(err)
	}
	approved := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if m := userCodeRE.FindStringSubmatch(stderr.String()); m != nil {
				approved <- approver.ApproveDevice(context.Background(), m[1], true)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		approved <- context.DeadlineExceeded
	}()
	r := e.cli("", &stderr, "login", "--scope", scope)
	if err := <-approved; err != nil {
		e.t.Fatalf("approving device code: %v", err)
	}
	if r.code != 0 || !strings.Contains(r.stderr, "Logged in") {
		e.t.Fatalf("login failed: %+v", r)
	}
}

func (e *e2e) mustRun(stdin string, args ...string) result {
	e.t.Helper()
	r := e.cli(stdin, nil, args...)
	if r.code != 0 {
		e.t.Fatalf("secretkit %v exited %d: %s", args, r.code, r.stderr)
	}
	return r
}

func TestEndToEnd(t *testing.T) {
	e := newE2E(t, server.Config{})

	r := e.cli("", nil, "list")
	if r.code != 1 || !strings.Contains(r.stderr, "not logged in") {
		t.Fatalf("list before login: %+v", r)
	}

	e.login("secrets:read secrets:write")

	stored, err := KeyringStore{}.Load(e.url)
	if err != nil || stored.RefreshToken == "" {
		t.Fatalf("token not in keychain: %+v %v", stored, err)
	}

	e.mustRun("fake-db-password\n", "set", "DB_PASSWORD")
	e.mustRun("", "set", "API_KEY", "fake-api-key-123")

	if r := e.mustRun("", "get", "DB_PASSWORD"); r.stdout != "fake-db-password\n" {
		t.Fatalf("get = %q (stdin newline should be trimmed)", r.stdout)
	}
	if r := e.mustRun("", "list"); !strings.Contains(r.stdout, "API_KEY") || !strings.Contains(r.stdout, "DB_PASSWORD") ||
		strings.Contains(r.stdout, "fake-") {
		t.Fatalf("list = %q", r.stdout)
	}

	// The child sees real values; its output is redacted.
	r = e.mustRun("", "run", "--", "sh", "-c",
		`printf '%s' "$DB_PASSWORD" | wc -c; echo "key=$API_KEY"; echo "err=$DB_PASSWORD" >&2`)
	if strings.TrimSpace(strings.Split(r.stdout, "\n")[0]) != "16" {
		t.Fatalf("DB_PASSWORD not injected: %q", r.stdout)
	}
	if !strings.Contains(r.stdout, "key=[REDACTED]") || !strings.Contains(r.stderr, "err=[REDACTED]") ||
		strings.Contains(r.stdout+r.stderr, "fake-") {
		t.Fatalf("output not redacted: stdout=%q stderr=%q", r.stdout, r.stderr)
	}

	r = e.cli("", nil, "run", "--only", "API_KEY", "--", "sh", "-c", `test -z "$DB_PASSWORD" && exit 7`)
	if r.code != 7 {
		t.Fatalf("--only / exit code: %+v", r)
	}

	e.mustRun("", "logout")
	if _, err := (KeyringStore{}).Load(e.url); err == nil {
		t.Fatal("token still in keychain after logout")
	}
	if _, err := e.srv.Tokens.Refresh(ClientID, stored.RefreshToken); err == nil {
		t.Fatal("refresh token still valid on server after logout")
	}
}

func TestEndToEndRefreshPersistsRotatedToken(t *testing.T) {
	// A TTL inside the SDK's 30s refresh leeway forces a refresh on every use.
	e := newE2E(t, server.Config{AccessTokenTTL: 20 * time.Second})
	e.login("secrets:read")
	before, _ := KeyringStore{}.Load(e.url)

	e.mustRun("", "list")
	after, _ := KeyringStore{}.Load(e.url)
	if after.RefreshToken == before.RefreshToken {
		t.Fatal("rotated refresh token was not saved to the keychain")
	}
	// A second process must start from the rotated token, or reuse
	// detection would revoke the session.
	e.mustRun("", "list")
}

func TestEndToEndScopeError(t *testing.T) {
	e := newE2E(t, server.Config{})
	e.login("secrets:read")
	r := e.cli("", nil, "set", "X", "fake-value")
	if r.code != 1 || !strings.Contains(r.stderr, "permission denied") {
		t.Fatalf("set with read-only scope: %+v", r)
	}
}

func TestEndToEndEnvToken(t *testing.T) {
	e := newE2E(t, server.Config{})
	e.srv.Tokens.AddStaticToken("fake-env-token-value", []string{server.ScopeRead, server.ScopeWrite})
	e.extEnv["SECRETKIT_TOKEN"] = "fake-env-token-value"

	e.mustRun("", "set", "TOKEN_ECHO", "fake-echo-value")
	// The CLI's own token is not passed to children, and would be redacted if it were printed.
	r := e.mustRun("", "run", "--", "sh", "-c", `echo "tok=${SECRETKIT_TOKEN:-unset}"; echo fake-env-token-value`)
	if !strings.Contains(r.stdout, "tok=unset") || !strings.Contains(r.stdout, "[REDACTED]") {
		t.Fatalf("stdout = %q", r.stdout)
	}
}
