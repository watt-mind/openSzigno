//! The token endpoint, and where what it issues is kept.
//!
//! Two things live here: the `POST` that turns an authorization code (or a
//! refresh token) into an access token, and the pair of files a login leaves
//! behind.
//!
//! # What is written, and where
//!
//! | File | What it holds |
//! | :--- | :--- |
//! | `access_token_file` | The bearer token, one line, nothing else. It is what `sign --csc` already reads. |
//! | `<access_token_file>.record.json` | When the token expires, the refresh token if one was issued, and the token endpoint that issued both. |
//!
//! Both are created with mode `0600` on Unix, and both are rewritten in place
//! by every login and every refresh. The token is never printed, never put in
//! `argv`, and never reaches the JSON envelope: what the envelope carries is
//! the path it was written to and the instant it expires.
//!
//! The record names its own token endpoint on purpose. A refresh has to happen
//! before discovery — an expired token would fail `info` too — so the endpoint
//! cannot be something a later `info` call supplies, and putting it in the
//! record means a refresh needs nothing from the configuration that the login
//! did not already resolve.
//!
//! # What reaches the wire
//!
//! One `application/x-www-form-urlencoded` body per exchange, through the same
//! transport every other request goes through, marked sensitive: it carries
//! the authorization code, the PKCE verifier and, where the client is a
//! confidential one, the client secret. Sensitive means `https` on every hop
//! unless the destination is loopback under `--online-allow-private`. The
//! client secret goes in the body, or in an HTTP Basic `Authorization` header
//! when the service's `info` says it takes `basic` authentication; never in
//! the URL.

use std::path::{Path, PathBuf};

use openszigno_author::sign::{SignError, SignErrorCode};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::online::Fetcher;

use super::oauth::encode;

/// The largest token response that will be read. A JWT access token with a
/// refresh token beside it is a few kilobytes.
const MAX_TOKEN_BYTES: u64 = 64 * 1024;

/// How close to expiry a stored token is treated as expired. A token that
/// outlives the run by a second is a token that expires mid-exchange.
const EXPIRY_MARGIN: u64 = 60;

fn failed(message: impl Into<String>) -> SignError {
    SignError::remote(SignErrorCode::CscLoginFailed, message)
}

// ---------------------------------------------------------------------------
// The token endpoint
// ---------------------------------------------------------------------------

/// What the token endpoint answered.
pub(crate) struct Tokens {
    pub(crate) access_token: Zeroizing<String>,
    pub(crate) refresh_token: Option<Zeroizing<String>>,
    /// Seconds from now, as the service reported them.
    pub(crate) expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct TokenBody {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

/// The client credentials a token request is made with.
pub(crate) struct Client<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) client_secret: Option<&'a str>,
    /// Whether the service's `info` reported `basic` among its `authType`
    /// values. It decides where the secret goes: an `Authorization: Basic`
    /// header, or the request body RFC 6749 section 2.3.1 also permits.
    pub(crate) basic: bool,
}

/// One exchange at the token endpoint.
///
/// `form` is the grant-specific half; the client credentials are added here,
/// in the one place that decides between the body and the header.
pub(crate) fn exchange(
    fetcher: &Fetcher,
    endpoint: &str,
    client: &Client<'_>,
    form: &[(&str, &str)],
) -> Result<Tokens, SignError> {
    let mut body = form
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>();
    body.push(format!("client_id={}", encode(client.client_id)));
    let mut authorization = None;
    match client.client_secret {
        Some(secret) if client.basic => {
            authorization = Some(Zeroizing::new(format!(
                "Basic {}",
                openszigno_author::sign::csc::encode_base64(
                    format!("{}:{}", encode(client.client_id), encode(secret)).as_bytes(),
                )
            )));
        }
        Some(secret) => body.push(format!("client_secret={}", encode(secret))),
        None => {}
    }
    let body = Zeroizing::new(body.join("&"));
    let answer = fetcher
        .post_form(
            endpoint,
            authorization.as_ref().map(|value| value.as_str()),
            &body,
            MAX_TOKEN_BYTES,
        )
        .map_err(|class| {
            SignError::remote(
                SignErrorCode::CscUnreachable,
                format!("the OAuth 2.0 token endpoint could not be reached ({class})"),
            )
        })?;
    let parsed: TokenBody = serde_json::from_slice(&answer.body).map_err(|_| {
        failed("the token endpoint answered something that is not a token response")
    })?;
    if answer.status != 200 {
        // Only `error` is read: `error_description` is free text a provider
        // writes, and nothing says it does not repeat the token back.
        return Err(failed(format!(
            "the token endpoint refused the exchange with HTTP {}{}",
            answer.status,
            parsed.error.map_or_else(String::new, |error| format!(
                " ({})",
                openszigno_core::sanitize_display(&error, 120)
            ))
        )));
    }
    let access_token = parsed
        .access_token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            SignError::remote(
                SignErrorCode::CscTokenUnusable,
                "the token endpoint answered without an access token",
            )
        })?;
    Ok(Tokens {
        access_token: Zeroizing::new(access_token),
        refresh_token: parsed
            .refresh_token
            .filter(|token| !token.is_empty())
            .map(Zeroizing::new),
        expires_in: parsed.expires_in,
    })
}

/// The authorization-code grant, with the PKCE verifier RFC 7636 requires.
pub(crate) fn redeem_code(
    fetcher: &Fetcher,
    endpoint: &str,
    client: &Client<'_>,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<Tokens, SignError> {
    exchange(
        fetcher,
        endpoint,
        client,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ],
    )
}

/// The refresh-token grant.
pub(crate) fn refresh(
    fetcher: &Fetcher,
    endpoint: &str,
    client: &Client<'_>,
    refresh_token: &str,
) -> Result<Tokens, SignError> {
    exchange(
        fetcher,
        endpoint,
        client,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ],
    )
}

// ---------------------------------------------------------------------------
// The stored record
// ---------------------------------------------------------------------------

/// What a login leaves beside the token file.
#[derive(Debug, Default, Deserialize, serde::Serialize)]
pub(crate) struct Record {
    /// The Unix instant the access token stops being usable, when the service
    /// said how long it lasts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at: Option<u64>,
    /// The refresh token, when one was issued. It is a secret, and the file
    /// holding it is created `0600`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_token: Option<String>,
    /// The token endpoint that issued both, so a refresh needs no discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) token_url: Option<String>,
}

impl Record {
    /// Whether the access token is expired, or close enough to it that a run
    /// starting now would not finish under it.
    pub(crate) fn is_expired(&self, now: u64) -> bool {
        self.expires_at
            .is_some_and(|expires| expires <= now.saturating_add(EXPIRY_MARGIN))
    }
}

/// The record that belongs to a token file.
pub(crate) fn record_path(token_path: &Path) -> PathBuf {
    let mut name = token_path.as_os_str().to_os_string();
    name.push(".record.json");
    PathBuf::from(name)
}

/// Read the record beside a token file. A missing record is `None`; an
/// unreadable one is a refusal, because silently treating a corrupt record as
/// "no expiry known" is how an expired token becomes a confusing `csc_rejected`.
pub(crate) fn load_record(token_path: &Path) -> Result<Option<Record>, SignError> {
    let path = record_path(token_path);
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|_| {
        SignError::remote(
            SignErrorCode::CscTokenUnusable,
            "the stored CSC token record cannot be read; run `openszigno csc login` again",
        )
    })
}

/// Write the token and its record, both `0600` on Unix.
pub(crate) fn store(
    token_path: &Path,
    tokens: &Tokens,
    token_url: &str,
    now: u64,
) -> Result<Record, SignError> {
    let record = Record {
        expires_at: tokens.expires_in.map(|seconds| now.saturating_add(seconds)),
        refresh_token: tokens.refresh_token.as_ref().map(|token| token.to_string()),
        token_url: Some(token_url.to_owned()),
    };
    write_private(token_path, tokens.access_token.as_bytes())?;
    let serialized = serde_json::to_vec_pretty(&record)
        .map_err(|_| failed("the CSC token record could not be built"))?;
    write_private(&record_path(token_path), &serialized)?;
    Ok(record)
}

/// Write a file only its owner can read.
///
/// The mode is set at creation, not afterwards: a file created `0644` and
/// chmod-ed later is world-readable for the length of the write, and a token
/// is exactly the thing that window matters for. An existing file is
/// truncated, because a login is meant to replace the token that is there.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SignError> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| {
        SignError::remote(
            SignErrorCode::CscTokenUnusable,
            "the CSC token file could not be created; check the path the configuration names",
        )
    })?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .map_err(|_| {
            SignError::remote(
                SignErrorCode::CscTokenUnusable,
                "the CSC token file could not be written",
            )
        })
}

#[cfg(test)]
#[path = "tokens_tests.rs"]
mod tests;
