package secretkit

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// scriptedServer replies with the given statuses in order, then 200.
func scriptedServer(t *testing.T, statuses []int, onRequest func(*http.Request)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1))
		if onRequest != nil {
			onRequest(r)
		}
		w.Header().Set("Content-Type", "application/json")
		if n <= len(statuses) {
			if statuses[n-1] == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "2")
			}
			w.WriteHeader(statuses[n-1])
			_, _ = io.WriteString(w, `{"error":"server_error"}`)
			return
		}
		switch r.URL.Path {
		case "/v1/secrets":
			_, _ = io.WriteString(w, `{"secrets":[]}`)
		case "/oauth/token":
			_, _ = io.WriteString(w, `{"access_token":"a","token_type":"Bearer","expires_in":60,"refresh_token":"r","scope":"secrets:read"}`)
		default:
			_, _ = io.WriteString(w, `{"name":"A","version":1,"updated_at":"2026-01-01T00:00:00Z"}`)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

func retryClient(t *testing.T, url string, sleeps *[]time.Duration) *Client {
	t.Helper()
	c, err := New(url, WithToken("fake-token"))
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(ctx context.Context, d time.Duration) error {
		*sleeps = append(*sleeps, d)
		return ctx.Err()
	}
	return c
}

func TestRetryOn5xxForIdempotentRequest(t *testing.T) {
	ts, calls := scriptedServer(t, []int{503, 500}, nil)
	var sleeps []time.Duration
	c := retryClient(t, ts.URL, &sleeps)
	if _, err := c.ListSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
	// Exponential: ~100ms then ~200ms, each with up to 20% jitter.
	if len(sleeps) != 2 || sleeps[0] < 100*time.Millisecond || sleeps[0] > 120*time.Millisecond ||
		sleeps[1] < 200*time.Millisecond || sleeps[1] > 240*time.Millisecond {
		t.Fatalf("sleeps = %v", sleeps)
	}
}

func TestRetryHonorsRetryAfterOn429(t *testing.T) {
	ts, calls := scriptedServer(t, []int{429}, nil)
	var sleeps []time.Duration
	c := retryClient(t, ts.URL, &sleeps)
	if _, err := c.ListSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(sleeps) != 1 || sleeps[0] != 2*time.Second {
		t.Fatalf("calls=%d sleeps=%v", calls.Load(), sleeps)
	}
}

func TestRetryReplaysPutBody(t *testing.T) {
	var bodies []string
	ts, _ := scriptedServer(t, []int{502}, func(r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
	})
	var sleeps []time.Duration
	c := retryClient(t, ts.URL, &sleeps)
	if _, err := c.PutSecret(context.Background(), "A", "fake-value"); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || bodies[0] != bodies[1] || bodies[0] == "" {
		t.Fatalf("bodies = %q", bodies)
	}
}

func TestNoRetryOn5xxForTokenPost(t *testing.T) {
	ts, calls := scriptedServer(t, []int{503}, nil)
	var sleeps []time.Duration
	c := retryClient(t, ts.URL, &sleeps)
	_, err := c.RefreshToken(context.Background(), "cli", "fake-refresh")
	if !errors.Is(err, ErrServer) {
		t.Fatalf("err = %v, want ErrServer", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("POST was retried: calls = %d", calls.Load())
	}
}

func TestRetryOn429ForTokenPost(t *testing.T) {
	ts, calls := scriptedServer(t, []int{429}, nil)
	var sleeps []time.Duration
	c := retryClient(t, ts.URL, &sleeps)
	if _, err := c.RefreshToken(context.Background(), "cli", "fake-refresh"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
}

func TestRetryGivesUpWithTypedError(t *testing.T) {
	ts, calls := scriptedServer(t, []int{500, 500, 500, 500, 500}, nil)
	var sleeps []time.Duration
	c := retryClient(t, ts.URL, &sleeps)
	_, err := c.ListSecrets(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 500 || !errors.Is(err, ErrServer) {
		t.Fatalf("err = %#v", err)
	}
	if calls.Load() != int32(DefaultRetryPolicy.MaxAttempts) {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestRetryStopsOnContextCancel(t *testing.T) {
	ts, calls := scriptedServer(t, []int{503, 503, 503}, nil)
	c, err := New(ts.URL, WithToken("fake-token"), WithRetryPolicy(RetryPolicy{MaxAttempts: 5, BaseDelay: time.Hour, MaxDelay: time.Hour}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = c.ListSecrets(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}
