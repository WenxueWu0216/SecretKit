# Error handling

Every error response has the same JSON body:

```json
{"error": "not_found", "error_description": "secret DB_PASSWORD not found"}
```

`error_description` never contains secret values.

## Error codes

| HTTP | `error` | Go (`errors.Is`) | Rust `Error` variant | When |
|---|---|---|---|---|
| 400 | `invalid_request` | `ErrInvalidRequest` | `InvalidRequest` | Malformed body, bad secret name, value over 64 KiB |
| 400 | `invalid_client` | `ErrInvalidRequest` | – | Missing `client_id` |
| 400 | `invalid_scope` | `ErrInvalidRequest` | – | Unknown scope requested |
| 400 | `unsupported_grant_type` | `ErrInvalidRequest` | – | Grant type other than device code / refresh |
| 400 | `authorization_pending` | `ErrAuthorizationPending` | – | Device flow not approved yet |
| 400 | `slow_down` | `ErrSlowDown` | – | Polling too fast |
| 400 | `access_denied` | `ErrAccessDenied` | – | User denied the device request |
| 400 | `expired_token` | `ErrExpiredToken` | – | Device code expired |
| 400 | `invalid_grant` | `ErrInvalidGrant` | – | Bad device code / verifier, or refresh token used, expired or revoked |
| 401 | `invalid_token` | `ErrUnauthorized` | `Unauthorized` | Missing, expired or revoked access token |
| 403 | `insufficient_scope` | `ErrForbidden` | `Forbidden` | Token lacks the scope |
| 404 | `not_found` | `ErrNotFound` | `NotFound` | Secret or user code does not exist |
| 429 | `rate_limited` | `ErrRateLimited` | `RateLimited { retry_after }` | Rate limit hit; `Retry-After` is set |
| 5xx | `server_error` | `ErrServer` | `Server { status }` | Server failure |

The Rust client only calls the secrets endpoints, so OAuth-only codes have
no variant. Network and decoding failures surface as `Error::Http`.

## Go SDK

Every non-2xx response is a `*secretkit.APIError` with `StatusCode`,
`Code`, `Description` and `RetryAfter`. Match categories with `errors.Is`
and inspect details with `errors.As`:

```go
_, err := client.GetSecret(ctx, "DB_PASSWORD")
var apiErr *secretkit.APIError
switch {
case errors.Is(err, secretkit.ErrNotFound):
	// create it
case errors.As(err, &apiErr):
	log.Printf("secretkit: %d %s", apiErr.StatusCode, apiErr.Code)
}
```

## Retries

The Go SDK retries automatically (`DefaultRetryPolicy`: 4 attempts in
total, 100 ms base delay doubling each time, up to 20% jitter, 5 s cap):

| Response | GET / PUT | POST (OAuth endpoints) |
|---|---|---|
| 429 | retried, waiting `Retry-After` if present | retried |
| 5xx | retried | not retried |
| transport error | retried | not retried |
| other 4xx | not retried | not retried |

POSTs are not retried on `5xx` because a refresh token may already have
been rotated by the failed request; replaying it would trigger reuse
detection and end the session. Retries stop as soon as the context is
cancelled. Use `WithRetryPolicy(secretkit.RetryPolicy{MaxAttempts: 1})` to
disable them.

The Rust client does not retry; it returns `Error::RateLimited` with the
`Retry-After` duration so the caller can decide.

## CLI

The CLI prints `secretkit: <message>` to stderr and exits with status 1.
Session problems (`invalid_grant`, `invalid_token`) are reported as
"session expired or revoked; run `secretkit login` again", and missing
scopes as "permission denied". `secretkit run` exits with the child's exit
status.
