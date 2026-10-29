// Package secretkit is a client for the SecretKit API. It wraps the
// generated client in package api with typed errors, retries, token
// refresh and the device authorization flow.
package secretkit

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/WenxueWu0216/SecretKit/sdk/go/api"
)

// Client is safe for concurrent use.
type Client struct {
	api         *api.ClientWithResponses
	tokens      TokenSource
	userAgent   string
	sleep       func(context.Context, time.Duration) error
	now         func() time.Time
	retryPolicy RetryPolicy
	httpClient  *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the underlying HTTP client. Retries wrap it.
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.httpClient = hc } }

// WithTokenSource sets where access tokens for secret operations come from.
func WithTokenSource(ts TokenSource) Option { return func(c *Client) { c.tokens = ts } }

// WithToken uses a fixed access token.
func WithToken(token string) Option { return WithTokenSource(StaticToken(token)) }

// WithRetryPolicy overrides DefaultRetryPolicy.
func WithRetryPolicy(p RetryPolicy) Option { return func(c *Client) { c.retryPolicy = p } }

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option { return func(c *Client) { c.userAgent = ua } }

// New creates a client for the server at baseURL.
func New(baseURL string, opts ...Option) (*Client, error) {
	c := &Client{
		userAgent:   "secretkit-go",
		sleep:       sleepCtx,
		now:         time.Now,
		retryPolicy: DefaultRetryPolicy,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	doer := &retryingDoer{client: c.httpClient, policy: c.retryPolicy, sleep: func(ctx context.Context, d time.Duration) error {
		return c.sleep(ctx, d)
	}}
	ac, err := api.NewClientWithResponses(baseURL, api.WithHTTPClient(doer), api.WithRequestEditorFn(c.setUserAgent))
	if err != nil {
		return nil, err
	}
	c.api = ac
	return c, nil
}

func (c *Client) setUserAgent(_ context.Context, req *http.Request) error {
	req.Header.Set("User-Agent", c.userAgent)
	return nil
}

var errNoTokenSource = errors.New("secretkit: no token source configured")

// authorized runs call with a bearer token. On a 401 it asks a refreshable
// token source for a new token and tries once more, which covers tokens
// that expired or were rotated between the expiry check and the request.
func (c *Client) authorized(ctx context.Context, call func(api.RequestEditorFn) error) error {
	if c.tokens == nil {
		return errNoTokenSource
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.tokens.Token(ctx)
		if err != nil {
			return err
		}
		err = call(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+tok)
			return nil
		})
		inv, canInvalidate := c.tokens.(invalidator)
		if attempt == 0 && canInvalidate && errors.Is(err, ErrUnauthorized) {
			inv.invalidate(tok)
			continue
		}
		return err
	}
}
