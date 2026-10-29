# SDK usage

## Go

```bash
go get github.com/WenxueWu0216/SecretKit/sdk/go/secretkit
```

### With an access token

```go
client, err := secretkit.New("http://127.0.0.1:8787", secretkit.WithToken(os.Getenv("SECRETKIT_TOKEN")))
if err != nil {
	log.Fatal(err)
}
secret, err := client.GetSecret(ctx, "DB_PASSWORD")
if err != nil {
	log.Fatal(err)
}
meta, err := client.PutSecret(ctx, "API_KEY", "fake-api-key")
list, err := client.ListSecrets(ctx) // metadata only, never values
```

A runnable version of this is `Example` in
`sdk/go/secretkit/example_test.go` (run by `go test`).

### Device login

```go
client, _ := secretkit.New(serverURL)
da, err := client.StartDeviceAuth(ctx, "my-app", "secrets:read")
if err != nil {
	log.Fatal(err)
}
fmt.Printf("Open %s and enter %s\n", da.VerificationURI, da.UserCode)
tok, err := client.PollToken(ctx, da) // honours interval and slow_down
if err != nil {
	log.Fatal(err)
}
```

The PKCE verifier is generated inside `StartDeviceAuth` and kept in the
unexported fields of `DeviceAuth`.

### Automatic refresh

```go
base, _ := secretkit.New(serverURL)
ts := base.NewRefreshingTokenSource("my-app", tok)
ts.OnRefresh = func(t secretkit.Token) error {
	return saveSomewhereSafe(t) // refresh tokens rotate; persist every new one
}
client, _ := secretkit.New(serverURL, secretkit.WithTokenSource(ts))
```

### Options

| Option | Default |
|---|---|
| `WithHTTPClient(*http.Client)` | `http.Client{Timeout: 30s}` |
| `WithRetryPolicy(RetryPolicy)` | `DefaultRetryPolicy` |
| `WithToken(string)` / `WithTokenSource(TokenSource)` | none (secret calls fail) |
| `WithUserAgent(string)` | `secretkit-go` |

All methods take a `context.Context`; cancelling it stops in-flight
requests, retry back-off and device polling.

### Regenerating the client

`sdk/go/api` is generated from the spec:

```bash
cd sdk/go/api && go generate
```

## Rust

`clients/rust` is a blocking client (reqwest with rustls, serde). It uses an
existing access token and does not implement login.

```rust
use secretkit_client::{Client, Error};

let client = Client::new("http://127.0.0.1:8787", "fake-dev-token")?;
// or Client::from_env() reading SECRETKIT_SERVER and SECRETKIT_TOKEN
for meta in client.list_secrets()? {
    println!("{} v{}", meta.name, meta.version);
}
match client.get_secret("DB_PASSWORD") {
    Ok(secret) => println!("{:?}", secret), // Debug prints value as [REDACTED]
    Err(Error::NotFound(_)) => println!("not set"),
    Err(e) => return Err(e),
}
```

Run its tests (they build and start the Go mock server):

```bash
cd clients/rust && cargo test
```
