# Quickstart

Requirements: Go 1.25+, and for `secretkit login`, an OS keychain (macOS
Keychain, Windows Credential Manager, or a Secret Service provider such as
gnome-keyring on Linux). Without a keychain, use the
[token-only path](#without-a-keychain).

## Build

```bash
go build -o bin/secretkit-server ./server/cmd/secretkit-server
go build -o bin/secretkit ./cmd/secretkit
```

## Start the mock server

```bash
./bin/secretkit-server
```

It listens on `http://127.0.0.1:8787` and keeps everything in memory.
The CLI uses that address by default; override it with `--server` or
`SECRETKIT_SERVER`.

## Log in

In a second terminal:

```bash
./bin/secretkit login
```

```text
To log in, open http://127.0.0.1:8787/device?user_code=SFSJ-LSSX
and confirm the code: SFSJ-LSSX
Waiting for approval (expires in 10m0s)...
```

The mock server has no web page. Approve the code with the endpoint that a
consent page would call, using the code printed above:

```bash
curl -X POST -d 'user_code=SFSJ-LSSX&action=approve' http://127.0.0.1:8787/oauth/device/verify
```

`login` then prints `Logged in to http://127.0.0.1:8787 (scopes: secrets:read secrets:write)`.

## Use secrets

```bash
echo 'fake-db-password' | ./bin/secretkit set DB_PASSWORD
./bin/secretkit set API_KEY fake-api-key-123
./bin/secretkit get DB_PASSWORD
./bin/secretkit list
```

Reading the value from stdin keeps it out of shell history; on a terminal
`set NAME` prompts with hidden input.

## Run a command with secrets

```bash
./bin/secretkit run -- sh -c 'echo "DB_PASSWORD has ${#DB_PASSWORD} chars"; echo "API_KEY=$API_KEY"'
```

```text
DB_PASSWORD has 16 chars
API_KEY=[REDACTED]
```

The child receives the real values; any value it prints is masked. Use
`--only NAME,...` to inject a subset. The exit code of the child is
returned.

## Log out

```bash
./bin/secretkit logout
```

This revokes the session on the server and deletes the keychain entry.

## Without a keychain

For CI or headless machines, start the server with a development token and
pass the same token to the CLI. No login or keychain is involved:

```bash
SECRETKIT_DEV_TOKEN=fake-dev-token ./bin/secretkit-server
```

```bash
SECRETKIT_TOKEN=fake-dev-token ./bin/secretkit list
```

## Shell completion

```bash
./bin/secretkit completion bash > /etc/bash_completion.d/secretkit
```

`zsh`, `fish` and `powershell` are also supported.
