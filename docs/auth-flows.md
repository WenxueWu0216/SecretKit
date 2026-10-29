# Auth flows

All endpoints are defined in `openapi/secretkit.yaml`. OAuth endpoints take
`application/x-www-form-urlencoded` bodies and return JSON.

## Device authorization with PKCE

1. The client generates a random verifier (43+ characters) and computes
   `code_challenge = BASE64URL(SHA256(verifier))`.
2. `POST /oauth/device/code` with `client_id`, `scope`, `code_challenge`,
   `code_challenge_method=S256`. The response has `device_code`,
   `user_code`, `verification_uri`, `expires_in` (600 s) and `interval` (5 s).
3. The client shows the user code and polls `POST /oauth/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`,
   `client_id` and `code_verifier`, waiting `interval` seconds between polls.
4. The user approves with `POST /oauth/device/verify` (`user_code`,
   `action=approve|deny`). In a real system this would be a web page behind
   a login; in the mock it is an open endpoint.
5. The next poll returns tokens if the verifier matches the challenge.

Poll responses before completion:

| `error` | Meaning | Client action |
|---|---|---|
| `authorization_pending` | Not approved yet. | Keep polling at the current interval. |
| `slow_down` | Polled faster than `interval`. | Add 5 seconds to the interval, keep polling. |
| `access_denied` | The user denied the request. | Stop. |
| `expired_token` | `expires_in` elapsed. | Stop; start a new login. |
| `invalid_grant` | Unknown device code, wrong client, or wrong verifier. | Stop. |

The Go SDK implements this loop in `Client.StartDeviceAuth` and
`Client.PollToken`; the CLI's `login` command uses it.

## Scopes

| Scope | Allows |
|---|---|
| `secrets:read` | `GET /v1/secrets`, `GET /v1/secrets/{name}` |
| `secrets:write` | `PUT /v1/secrets/{name}` |

`login` requests both by default; `secretkit login --scope secrets:read`
requests read-only access. A request without the needed scope gets
`403 insufficient_scope` with a `WWW-Authenticate` header naming the scope.

## Tokens and refresh

Access tokens last 15 minutes (`-access-ttl`), refresh tokens 24 hours
(`-refresh-ttl`). Refresh with:

```text
POST /oauth/token
grant_type=refresh_token&client_id=secretkit-cli&refresh_token=...
```

Every refresh returns a new refresh token and invalidates the old one.
Presenting an old refresh token again revokes the whole session (all tokens
from that login). The SDK refreshes 30 seconds before expiry and retries a
request once after a `401`; the CLI saves each new token pair to the
keychain.

## Revocation

`POST /oauth/revoke` with `token=<refresh token>` ends the session and all
its access tokens. Revoking an access token ends only that token. Unknown
tokens return `200`, as RFC 7009 requires. `secretkit logout` revokes and
then deletes the keychain entry, and still deletes the entry if the server
is unreachable.

## Static development tokens

`SECRETKIT_DEV_TOKEN=<token> secretkit-server` registers a non-expiring
access token with the scopes in `-dev-token-scope` (default: both). It is
read from the environment so it does not appear in process listings. Clients
use it as `SECRETKIT_TOKEN` (CLI, Rust client) or `secretkit.WithToken` (Go).
