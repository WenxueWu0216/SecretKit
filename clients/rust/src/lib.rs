//! Client for the SecretKit API.
//!
//! It reads secrets with an access token obtained elsewhere (for example
//! from `secretkit login` or a CI variable); it does not implement the
//! device login flow.
//!
//! ```no_run
//! let client = secretkit_client::Client::from_env()?;
//! let secret = client.get_secret("DB_PASSWORD")?;
//! println!("version {}", secret.version);
//! # Ok::<(), secretkit_client::Error>(())
//! ```

use std::fmt;
use std::time::Duration;

use reqwest::blocking::Response;
use reqwest::header::RETRY_AFTER;
use reqwest::StatusCode;
use serde::Deserialize;

/// Default server address, matching the Go CLI.
pub const DEFAULT_SERVER: &str = "http://127.0.0.1:8787";

/// Errors returned by [`Client`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unauthorized: {0}")]
    Unauthorized(ApiError),
    #[error("forbidden: {0}")]
    Forbidden(ApiError),
    #[error("not found: {0}")]
    NotFound(ApiError),
    #[error("rate limited: {error}")]
    RateLimited {
        error: ApiError,
        retry_after: Option<Duration>,
    },
    #[error("invalid request: {0}")]
    InvalidRequest(ApiError),
    #[error("server error ({status}): {error}")]
    Server { status: u16, error: ApiError },
    #[error("invalid secret name {0:?}: must match [A-Za-z_][A-Za-z0-9_]{{0,127}}")]
    InvalidName(String),
    #[error("missing configuration: {0}")]
    Config(&'static str),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

/// The error body defined by the API's `Error` schema.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ApiError {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error_description {
            Some(d) => write!(f, "{}: {}", self.error, d),
            None => f.write_str(&self.error),
        }
    }
}

/// Secret metadata as returned by `list_secrets`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SecretMetadata {
    pub name: String,
    pub version: i64,
    /// RFC 3339 timestamp.
    pub updated_at: String,
}

/// A secret including its value.
#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct Secret {
    pub name: String,
    pub version: i64,
    pub updated_at: String,
    pub value: String,
}

// Debug output ends up in logs and panic messages, so it omits the value.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("updated_at", &self.updated_at)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
struct SecretList {
    secrets: Vec<SecretMetadata>,
}

/// A blocking SecretKit client authenticated with a bearer token.
pub struct Client {
    base_url: String,
    token: String,
    http: reqwest::blocking::Client,
}

// Hand-written so the token never appears in debug output.
impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Creates a client for `base_url` using `token` as the bearer token.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self, Error> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("secretkit-rust/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http,
        })
    }

    /// Creates a client from `SECRETKIT_SERVER` (optional) and `SECRETKIT_TOKEN`.
    pub fn from_env() -> Result<Self, Error> {
        let token = std::env::var("SECRETKIT_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .ok_or(Error::Config("SECRETKIT_TOKEN is not set"))?;
        let server = std::env::var("SECRETKIT_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.into());
        Self::new(server, token)
    }

    /// Lists secret metadata, sorted by name. Values are never included.
    pub fn list_secrets(&self) -> Result<Vec<SecretMetadata>, Error> {
        let resp = self.get("/v1/secrets")?;
        Ok(resp.json::<SecretList>()?.secrets)
    }

    /// Fetches a secret and its value.
    pub fn get_secret(&self, name: &str) -> Result<Secret, Error> {
        // Validated locally so a name cannot alter the request path.
        if !valid_name(name) {
            return Err(Error::InvalidName(name.to_string()));
        }
        Ok(self.get(&format!("/v1/secrets/{name}"))?.json()?)
    }

    fn get(&self, path: &str) -> Result<Response, Error> {
        let resp = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .send()?;
        if resp.status().is_success() {
            Ok(resp)
        } else {
            Err(error_from_response(resp))
        }
    }
}

fn error_from_response(resp: Response) -> Error {
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs);
    // A proxy may answer with a non-JSON body; keep the status in that case.
    let body = resp.json::<ApiError>().unwrap_or_else(|_| ApiError {
        error: status.canonical_reason().unwrap_or("unknown").to_string(),
        error_description: None,
    });
    map_status(status, body, retry_after)
}

fn map_status(status: StatusCode, error: ApiError, retry_after: Option<Duration>) -> Error {
    match status {
        StatusCode::UNAUTHORIZED => Error::Unauthorized(error),
        StatusCode::FORBIDDEN => Error::Forbidden(error),
        StatusCode::NOT_FOUND => Error::NotFound(error),
        StatusCode::TOO_MANY_REQUESTS => Error::RateLimited { error, retry_after },
        s if s.is_server_error() => Error::Server {
            status: s.as_u16(),
            error,
        },
        _ => Error::InvalidRequest(error),
    }
}

/// Reports whether `name` is a valid secret name (a valid env var name).
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    match bytes.first() {
        Some(c) if c.is_ascii_alphabetic() || *c == b'_' => {}
        _ => return false,
    }
    bytes.len() <= 128
        && bytes
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        for ok in ["A", "_x", "DB_PASSWORD", "a1"] {
            assert!(valid_name(ok), "{ok}");
        }
        let too_long = "A".repeat(129);
        for bad in ["", "1A", "A-B", "../x", "A B", too_long.as_str()] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn status_mapping() {
        let e = ApiError::default;
        assert!(matches!(
            map_status(StatusCode::UNAUTHORIZED, e(), None),
            Error::Unauthorized(_)
        ));
        assert!(matches!(
            map_status(StatusCode::FORBIDDEN, e(), None),
            Error::Forbidden(_)
        ));
        assert!(matches!(
            map_status(StatusCode::NOT_FOUND, e(), None),
            Error::NotFound(_)
        ));
        assert!(matches!(
            map_status(StatusCode::TOO_MANY_REQUESTS, e(), Some(Duration::from_secs(2))),
            Error::RateLimited { retry_after: Some(d), .. } if d == Duration::from_secs(2)
        ));
        assert!(matches!(
            map_status(StatusCode::BAD_GATEWAY, e(), None),
            Error::Server { status: 502, .. }
        ));
        assert!(matches!(
            map_status(StatusCode::BAD_REQUEST, e(), None),
            Error::InvalidRequest(_)
        ));
    }

    #[test]
    fn debug_hides_value_and_token() {
        let s = Secret {
            name: "N".into(),
            version: 1,
            updated_at: "2026-01-01T00:00:00Z".into(),
            value: "fake-secret-value".into(),
        };
        assert!(!format!("{s:?}").contains("fake-secret-value"));
        let c = Client::new("http://127.0.0.1:1", "fake-token-value").unwrap();
        assert!(!format!("{c:?}").contains("fake-token-value"));
    }

    #[test]
    fn invalid_name_is_rejected_before_request() {
        // Port 1 is never listening; reaching the network would yield Error::Http.
        let c = Client::new("http://127.0.0.1:1", "t").unwrap();
        assert!(matches!(
            c.get_secret("../admin"),
            Err(Error::InvalidName(_))
        ));
    }
}
