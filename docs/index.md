# SecretKit

SecretKit is a secrets CLI and SDK built around a local mock server:

- **`secretkit` CLI** (Go): device-flow login with PKCE, tokens in the OS
  keychain, `get`/`set`/`list`, and `run -- <cmd>` to inject secrets as
  environment variables with output redaction.
- **Go SDK**: a client generated from the OpenAPI spec plus a wrapper with
  typed errors, retries and token refresh.
- **Rust client**: token-based `get`/`list` with typed errors.
- **Mock server** (Go, in-memory): implements the spec, for local use and tests.

Start with the [quickstart](quickstart.md). The [design doc](design.md)
covers the threat model and tradeoffs.
