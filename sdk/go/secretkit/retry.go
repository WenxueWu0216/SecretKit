package secretkit

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// RetryPolicy controls retries of 429 and 5xx responses and transport errors.
type RetryPolicy struct {
	// MaxAttempts includes the first request. 1 disables retries.
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

// DefaultRetryPolicy retries up to 3 times with 100ms, 200ms, 400ms (+jitter).
var DefaultRetryPolicy = RetryPolicy{MaxAttempts: 4, BaseDelay: 100 * time.Millisecond, MaxDelay: 5 * time.Second}

// retryingDoer wraps an http.Client. A 429 means the server did not process
// the request, so any method is retried. 5xx and transport errors are only
// retried for idempotent methods: replaying a POST to /oauth/token could
// burn a single-use refresh token.
type retryingDoer struct {
	client *http.Client
	policy RetryPolicy
	sleep  func(context.Context, time.Duration) error
}

func (d *retryingDoer) Do(req *http.Request) (*http.Response, error) {
	attempts := max(d.policy.MaxAttempts, 1)
	for attempt := 1; ; attempt++ {
		resp, err := d.client.Do(req)
		if attempt >= attempts || !d.shouldRetry(req, resp, err) {
			return resp, err
		}
		delay := d.backoff(attempt, resp)
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
		}
		if err := d.sleep(req.Context(), delay); err != nil {
			return nil, err
		}
		// shouldRetry guarantees GetBody is set whenever there is a body.
		if req.Body != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req.Body = body
		}
	}
}

func (d *retryingDoer) shouldRetry(req *http.Request, resp *http.Response, err error) bool {
	if req.Context().Err() != nil {
		return false
	}
	if req.Body != nil && req.GetBody == nil {
		return false
	}
	if err != nil {
		return idempotent(req.Method)
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return true
	case resp.StatusCode >= 500:
		return idempotent(req.Method)
	}
	return false
}

func idempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions:
		return true
	}
	return false
}

func (d *retryingDoer) backoff(attempt int, resp *http.Response) time.Duration {
	if resp != nil {
		if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs >= 0 {
			return min(time.Duration(secs)*time.Second, d.policy.MaxDelay)
		}
	}
	delay := d.policy.BaseDelay << (attempt - 1)
	if delay <= 0 || delay > d.policy.MaxDelay {
		delay = d.policy.MaxDelay
	}
	// Up to 20% jitter so concurrent clients do not retry in lockstep.
	jitter := time.Duration(rand.Int64N(int64(delay)/5 + 1)) //nolint:gosec // jitter needs no cryptographic randomness
	return delay + jitter
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
