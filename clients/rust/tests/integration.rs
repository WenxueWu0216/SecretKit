//! Runs the client against the Go mock server. The server binary is taken
//! from SECRETKIT_SERVER_BIN, or built with `go build` on first use.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

use secretkit_client::{Client, Error};

fn server_bin() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Ok(p) = std::env::var("SECRETKIT_SERVER_BIN") {
            return PathBuf::from(p);
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("secretkit-server");
        let status = Command::new("go")
            .args(["build", "-o"])
            .arg(&out)
            .arg("./server/cmd/secretkit-server")
            .current_dir(&root)
            .status()
            .expect("running `go build` (set SECRETKIT_SERVER_BIN to skip)");
        assert!(status.success(), "go build failed");
        out
    })
}

struct MockServer {
    child: Child,
    url: String,
}

impl MockServer {
    fn start(dev_token: &str, scope: &str) -> Self {
        Self::start_with(dev_token, &["-dev-token-scope", scope])
    }

    fn start_with(dev_token: &str, extra_args: &[&str]) -> Self {
        let mut child = Command::new(server_bin())
            .args(["-addr", "127.0.0.1:0", "-quiet"])
            .args(extra_args)
            .env("SECRETKIT_DEV_TOKEN", dev_token)
            .stdout(Stdio::piped())
            .spawn()
            .expect("starting mock server");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let url = line
            .trim()
            .strip_prefix("listening on ")
            .expect("unexpected server banner")
            .to_string();
        MockServer { child, url }
    }

    fn put(&self, token: &str, name: &str, value: &str) {
        let resp = reqwest::blocking::Client::new()
            .put(format!("{}/v1/secrets/{name}", self.url))
            .bearer_auth(token)
            .json(&serde_json::json!({ "value": value }))
            .send()
            .unwrap();
        assert!(
            resp.status().is_success(),
            "seeding {name}: {}",
            resp.status()
        );
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const TOKEN: &str = "fake-rust-test-token";

#[test]
fn get_and_list_secrets() {
    let srv = MockServer::start(TOKEN, "secrets:read secrets:write");
    srv.put(TOKEN, "DB_PASSWORD", "fake-db-password");
    srv.put(TOKEN, "API_KEY", "fake-api-key");
    srv.put(TOKEN, "API_KEY", "fake-api-key-v2");

    let client = Client::new(&srv.url, TOKEN).unwrap();
    let list = client.list_secrets().unwrap();
    let names: Vec<_> = list.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["API_KEY", "DB_PASSWORD"]);
    assert_eq!(list[0].version, 2);

    let secret = client.get_secret("API_KEY").unwrap();
    assert_eq!(secret.value, "fake-api-key-v2");
    assert_eq!(secret.version, 2);
}

#[test]
fn typed_errors() {
    let srv = MockServer::start(TOKEN, "secrets:read");

    let client = Client::new(&srv.url, TOKEN).unwrap();
    match client.get_secret("MISSING") {
        Err(Error::NotFound(e)) => assert_eq!(e.error, "not_found"),
        other => panic!("expected NotFound, got {other:?}"),
    }

    let bad = Client::new(&srv.url, "fake-wrong-token").unwrap();
    match bad.list_secrets() {
        Err(Error::Unauthorized(e)) => assert_eq!(e.error, "invalid_token"),
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[test]
fn missing_scope_is_forbidden() {
    let srv = MockServer::start(TOKEN, "secrets:write");
    let client = Client::new(&srv.url, TOKEN).unwrap();
    match client.list_secrets() {
        Err(Error::Forbidden(e)) => assert_eq!(e.error, "insufficient_scope"),
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

#[test]
fn rate_limit_reports_retry_after() {
    let srv = MockServer::start_with(TOKEN, &["-rate-limit", "1"]);

    let client = Client::new(&srv.url, TOKEN).unwrap();
    client.list_secrets().unwrap();
    match client.list_secrets() {
        Err(Error::RateLimited { retry_after, .. }) => {
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(1)))
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}
