package cli

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/zalando/go-keyring"
)

// syncBuffer is read by the test while the CLI writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestLogsAreRedacted(t *testing.T) {
	var stderr syncBuffer
	a := newApp(Env{Stderr: &stderr})
	a.verbose = true
	a.setupLogging()
	a.redactions.Add("fake-log-secret")

	a.log.Debug("connecting", "dsn", "postgres://u:fake-log-secret@db/x")
	a.log.Error("request failed", "error", errors.New("bad value fake-log-secret"))
	_ = a.logOut.Flush()

	out := stderr.String()
	if strings.Contains(out, "fake-log-secret") {
		t.Fatalf("secret in logs: %s", out)
	}
	if strings.Count(out, "[REDACTED]") != 2 {
		t.Fatalf("expected two redactions: %s", out)
	}
}

func TestKeychainUnavailableError(t *testing.T) {
	keyring.MockInitWithError(errors.New("dbus: no session bus"))
	t.Cleanup(keyring.MockInit)

	_, err := KeyringStore{}.Load("http://127.0.0.1:8787")
	if !errors.Is(err, ErrKeychainUnavailable) {
		t.Fatalf("err = %v, want ErrKeychainUnavailable", err)
	}
	if !strings.Contains(err.Error(), "SECRETKIT_TOKEN") {
		t.Fatalf("error should mention the fallback: %v", err)
	}
}

func TestKeychainNotLoggedIn(t *testing.T) {
	keyring.MockInit()
	if _, err := (KeyringStore{}).Load("http://nowhere"); !errors.Is(err, errNotLoggedIn) {
		t.Fatalf("err = %v, want errNotLoggedIn", err)
	}
}

func TestChildEnv(t *testing.T) {
	got := childEnv(
		[]string{"PATH=/bin", "API_KEY=old", "SECRETKIT_TOKEN=fake-cli-token"},
		map[string]string{"API_KEY": "new", "DB_URL": "fake-db"},
	)
	want := []string{"PATH=/bin", "API_KEY=new", "DB_URL=fake-db"}
	if strings.Join(got, ";") != strings.Join(want, ";") {
		t.Fatalf("childEnv = %v, want %v", got, want)
	}
}
