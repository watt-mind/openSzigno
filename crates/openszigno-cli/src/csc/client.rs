//! The socket half of the CSC backend: one bounded `POST` per operation.
//!
//! Every request goes through the same [`Fetcher`]
//! that `verify --online` fetches revocation data with, so a CSC exchange gets
//! the destination policy, the pinned address resolution, the connect and
//! total timeouts, the redirect rules and a size cap without a second HTTP
//! client in this binary having to keep the same promises separately.
//!
//! The bearer token is put in the `Authorization` header and nowhere else. It
//! is not in the URL, not in the body, not in a message and not in the JSON
//! envelope: a refusal quotes the HTTP status and the CSC `error` string, and
//! a service that echoed the token back inside `error_description` would still
//! not get it printed, because only `error` is read.

use openszigno_author::sign::{SignError, SignErrorCode};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::online::Fetcher;

/// The largest CSC response that will be read. A certificate chain is the
/// biggest thing one carries and runs to a few kilobytes.
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// A CSC service, its base URL and the token that reaches it.
pub(crate) struct Client {
    fetcher: Fetcher,
    base_url: String,
    token: Zeroizing<String>,
}

/// The error object a CSC service answers a refusal with.
#[derive(Deserialize)]
struct ServiceError {
    #[serde(default)]
    error: Option<String>,
}

impl Client {
    pub(crate) fn new(fetcher: Fetcher, base_url: &str, token: Zeroizing<String>) -> Self {
        Self {
            fetcher,
            base_url: base_url.to_owned(),
            token,
        }
    }

    /// One CSC operation: `POST <base>/<operation>` with a JSON body.
    ///
    /// A transport failure is `csc_unreachable` and names the class the
    /// transport reported — `timeout`, `destination_refused: …` and the rest —
    /// because the remedies differ and a bare "it did not work" is not
    /// actionable. A service that answered is `csc_rejected`, with its status
    /// and its own `error` string.
    pub(crate) fn post(&self, operation: &str, body: &str) -> Result<Vec<u8>, SignError> {
        let url = format!("{}/{operation}", self.base_url);
        let answer = self
            .fetcher
            .post_json(&url, &self.token, body, MAX_RESPONSE_BYTES)
            .map_err(|class| {
                SignError::remote(
                    SignErrorCode::CscUnreachable,
                    format!("the CSC service could not be reached for {operation} ({class})"),
                )
            })?;
        if answer.status == 200 {
            return Ok(answer.body);
        }
        Err(SignError::remote(
            SignErrorCode::CscRejected,
            format!(
                "the CSC service refused {operation} with HTTP {}{}",
                answer.status,
                described(&answer.body)
            ),
        ))
    }
}

/// The CSC `error` string of a refusal, as a suffix, when there is one.
///
/// Only `error` is read. `error_description` is free text a service writes and
/// this tool has no way to know a provider has not put a token, a credential
/// identifier or a user's name in it.
fn described(body: &[u8]) -> String {
    let Ok(parsed) = serde_json::from_slice::<ServiceError>(body) else {
        return String::new();
    };
    parsed
        .error
        .filter(|value| !value.is_empty())
        .map(|value| format!(" ({})", sanitize(&value)))
        .unwrap_or_default()
}

/// Bound and strip a value taken from a remote answer before it reaches a
/// message, exactly as every other value taken from input is bounded.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(120)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_quotes_the_error_string_and_nothing_else() {
        assert_eq!(
            described(br#"{"error":"invalid_request","error_description":"Bearer eyJhbGci"}"#),
            " (invalid_request)"
        );
        assert_eq!(described(b"<html>a proxy error page</html>"), "");
        assert_eq!(described(br#"{"error":""}"#), "");
    }

    #[test]
    fn a_control_character_or_an_essay_never_reaches_a_message() {
        let described = described(br#"{"error":"invalid"}"#);
        assert!(!described.contains('\u{7}'));
        let long = format!(r#"{{"error":"{}"}}"#, "x".repeat(400));
        assert!(described_length(&long) <= 120);
    }

    fn described_length(body: &str) -> usize {
        described(body.as_bytes())
            .trim_matches(|c| c == ' ' || c == '(' || c == ')')
            .chars()
            .count()
    }
}
