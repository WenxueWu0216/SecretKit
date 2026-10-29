package secretkit

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/WenxueWu0216/SecretKit/server"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testEnv runs a real mock server whose clock only moves when the SDK
// sleeps, so polling and expiry tests are deterministic and instant.
type testEnv struct {
	srv    *server.Server
	clock  *fakeClock
	client *Client
	sleeps []time.Duration
	// onSleep runs after the clock advances, e.g. to approve a device code.
	onSleep func(n int)
}

func newTestEnv(t *testing.T, cfg server.Config, opts ...Option) *testEnv {
	t.Helper()
	env := &testEnv{clock: &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}
	cfg.Now = env.clock.Now
	env.srv = server.New(cfg)
	ts := httptest.NewServer(env.srv)
	t.Cleanup(ts.Close)

	c, err := New(ts.URL, opts...)
	if err != nil {
		t.Fatal(err)
	}
	c.now = env.clock.Now
	c.sleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		env.sleeps = append(env.sleeps, d)
		env.clock.Advance(d)
		if env.onSleep != nil {
			env.onSleep(len(env.sleeps))
		}
		return nil
	}
	env.client = c
	return env
}
