//! The browser half of a CSC exchange: PKCE, the authorization URL, and the
//! loopback listener the authorization code comes back to.
//!
//! Nothing here opens an outbound socket. This module builds the URL a person
//! opens, binds a listener on `127.0.0.1`, and reads exactly one redirect off
//! it; the token request that follows goes through [`super::tokens`] and the
//! transport `verify --online` uses.
//!
//! # Why a loopback listener
//!
//! RFC 8252 section 7.3 is the shape a native application redirects with: the
//! client binds a port on the loopback interface, and the authorization server
//! sends the user's browser back to it. There is no other place a
//! command-line tool can receive a redirect without a hosted callback, and a
//! hosted callback is a third party in possession of authorization codes.
//! The port is ephemeral by default, which is what the same section asks for,
//! and the configuration may pin one because some deployments register an
//! exact `redirect_uri`.
//!
//! # What the listener accepts
//!
//! One request, from the loopback interface, whose path is the redirect path.
//! Anything else gets a `404` and is not read further. The `state` parameter
//! is compared before the code is looked at, so a code that arrived under a
//! `state` this run did not issue is discarded unused and the run stops with
//! `csc_state_mismatch`. The listener stops on the first answered redirect and
//! on a deadline, so a login nobody completes ends rather than waits forever.
//!
//! # PKCE
//!
//! RFC 7636 with `S256` and nothing else: a 32-byte verifier from the
//! operating system's random source, base64url without padding, and its
//! SHA-256 as the challenge. The verifier is held in a `Zeroizing` buffer, is
//! sent only in the token request body, and never reaches `argv`, a message or
//! the envelope. `plain` is not offered: a downgrade to it is the one thing
//! PKCE exists to prevent.

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use openszigno_author::sign::{SignError, SignErrorCode};
use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// How long a redirect listener waits for the browser before it gives up. A
/// consent screen with a PIN, a push notification and a scroll takes minutes;
/// nothing takes five.
pub(crate) const REDIRECT_TIMEOUT: Duration = Duration::from_secs(300);

/// The redirect path used when the configuration names no `redirect_uri`.
const DEFAULT_REDIRECT_PATH: &str = "/callback";

/// The largest request head the listener will read. A redirect is a `GET` with
/// a query string; anything past this is not one.
const MAX_REQUEST_BYTES: usize = 16 * 1024;

fn failed(message: impl Into<String>) -> SignError {
    SignError::remote(SignErrorCode::CscLoginFailed, message)
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

/// One RFC 7636 code verifier and the `S256` challenge derived from it.
pub(crate) struct Pkce {
    pub(crate) verifier: Zeroizing<String>,
    pub(crate) challenge: String,
}

/// A fresh verifier and its challenge.
pub(crate) fn pkce() -> Pkce {
    let verifier = Zeroizing::new(random_value());
    let challenge = base64url(&Sha256::digest(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
    }
}

/// 32 bytes from the operating system's random source, base64url without
/// padding. It is what both the PKCE verifier and the `state` are made of:
/// 256 bits of entropy each, which is the length RFC 7636 section 4.1 permits
/// at its upper end and far past what guessing reaches.
pub(crate) fn random_value() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64url(&bytes)
}

/// base64url without padding (RFC 4648 section 5).
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut block = [0_u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let value = u32::from(block[0]) << 16 | u32::from(block[1]) << 8 | u32::from(block[2]);
        let characters = [
            ALPHABET[(value >> 18) as usize & 0x3f],
            ALPHABET[(value >> 12) as usize & 0x3f],
            ALPHABET[(value >> 6) as usize & 0x3f],
            ALPHABET[value as usize & 0x3f],
        ];
        // One input byte yields two output characters, two yield three; the
        // padding an unpadded encoding would carry is simply not emitted.
        for character in &characters[..chunk.len() + 1] {
            out.push(char::from(*character));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The authorization URL
// ---------------------------------------------------------------------------

/// What the credential round has to say about the signature it authorises.
///
/// Every field of it is bound into the authorization request, because that is
/// what makes the resulting token a *signature* authorisation rather than a
/// standing permission: the service shows the user how many signatures, over
/// which hashes, with which credential, and the token it issues covers those
/// and nothing else.
pub(crate) struct CredentialRound<'a> {
    pub(crate) credential_id: &'a str,
    pub(crate) num_signatures: u32,
    pub(crate) hashes: &'a [String],
    pub(crate) hash_algorithm_oid: &'a str,
    /// Whether the service's `info` reported `supportsRar`. It decides between
    /// RFC 9396 `authorization_details` and the plain query parameters; the
    /// three surveyed deployments disagree, so neither form is assumed.
    pub(crate) rar: bool,
}

/// Everything one authorization request carries.
pub(crate) struct AuthorizationRequest<'a> {
    pub(crate) endpoint: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) redirect_uri: &'a str,
    pub(crate) state: &'a str,
    pub(crate) challenge: &'a str,
    /// `None` is the `scope=service` round; `Some` is `scope=credential`.
    pub(crate) credential: Option<CredentialRound<'a>>,
}

impl AuthorizationRequest<'_> {
    /// The URL a person opens. It carries no secret: the client identifier is
    /// public, the challenge is a digest, and the verifier behind it stays in
    /// this process.
    pub(crate) fn url(&self) -> String {
        let scope = if self.credential.is_some() {
            "credential"
        } else {
            "service"
        };
        let mut query = vec![
            ("response_type".to_owned(), "code".to_owned()),
            ("client_id".to_owned(), self.client_id.to_owned()),
            ("redirect_uri".to_owned(), self.redirect_uri.to_owned()),
            ("scope".to_owned(), scope.to_owned()),
            ("state".to_owned(), self.state.to_owned()),
            ("code_challenge".to_owned(), self.challenge.to_owned()),
            ("code_challenge_method".to_owned(), "S256".to_owned()),
        ];
        if let Some(round) = &self.credential {
            query.extend(round.parameters());
        }
        let encoded = query
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let separator = if self.endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{}{separator}{encoded}", self.endpoint)
    }
}

impl CredentialRound<'_> {
    /// The credential parameters, in whichever of the two forms the service
    /// said it takes.
    fn parameters(&self) -> Vec<(String, String)> {
        if self.rar {
            return vec![("authorization_details".to_owned(), self.details())];
        }
        vec![
            ("credentialID".to_owned(), self.credential_id.to_owned()),
            ("numSignatures".to_owned(), self.num_signatures.to_string()),
            ("hashes".to_owned(), self.hashes.join(",")),
            (
                "hashAlgorithmOID".to_owned(),
                self.hash_algorithm_oid.to_owned(),
            ),
        ]
    }

    /// The RFC 9396 `authorization_details` object, as CSC API v2 profiles it:
    /// one `credential` element naming the credential, the digests, and the
    /// algorithm they were produced with.
    fn details(&self) -> String {
        let digests = self
            .hashes
            .iter()
            .map(|hash| serde_json::json!({"hash": hash, "label": "openSzigno XAdES signature"}))
            .collect::<Vec<_>>();
        serde_json::json!([{
            "type": "credential",
            "credentialID": self.credential_id,
            "documentDigests": digests,
            "hashAlgorithmOID": self.hash_algorithm_oid,
        }])
        .to_string()
    }
}

/// Percent-encode one query component. Everything outside the RFC 3986
/// unreserved set is escaped, `+` and `&` and `/` included, so a value a
/// service chose cannot add a parameter of its own.
pub(crate) fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(*byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Percent-decode one query component, `+` read as a space.
fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or_default();
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            other => out.push(other),
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// The loopback listener
// ---------------------------------------------------------------------------

/// A bound loopback redirect listener and the `redirect_uri` that names it.
pub(crate) struct Listener {
    listener: TcpListener,
    path: String,
    redirect_uri: String,
}

impl Listener {
    /// Bind the listener the redirect comes back to.
    ///
    /// Without a configured `redirect_uri` the port is ephemeral and the path
    /// is `/callback`. With one, the path is the configured path, and the port
    /// is the configured port when it is neither absent nor `0`: a deployment
    /// that registered an exact redirect needs that exact redirect, and one
    /// that registered `:0` is asking for the ephemeral port RFC 8252 prefers.
    /// The host is always `127.0.0.1`, whatever the configuration wrote, so a
    /// name that resolves elsewhere cannot move the listener off the machine.
    pub(crate) fn bind(configured: Option<&str>) -> Result<Self, SignError> {
        let (port, path) = configured.map_or((0, DEFAULT_REDIRECT_PATH.to_owned()), split);
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .map_err(|_| failed("the loopback redirect listener could not be bound"))?;
        let bound = listener
            .local_addr()
            .map_err(|_| failed("the loopback redirect listener has no address"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| failed("the loopback redirect listener could not be configured"))?;
        Ok(Self {
            listener,
            redirect_uri: format!("http://127.0.0.1:{}{path}", bound.port()),
            path,
        })
    }

    pub(crate) fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Wait for the redirect and return the authorization code it carried.
    ///
    /// The `state` is checked before the code is read, and a mismatch stops
    /// the run rather than continuing to listen: a redirect under a `state`
    /// this run did not issue is either a stale browser tab or somebody else's
    /// code, and neither is a thing to sign with.
    pub(crate) fn wait(
        &self,
        state: &str,
        timeout: Duration,
    ) -> Result<Zeroizing<String>, SignError> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if let Some(answer) = self.serve(stream, state) {
                        return answer;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(failed(
                            "no authorization redirect arrived at the loopback listener before it gave up; open the URL that was printed, or pass --no-interactive to refuse the round instead of waiting",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    return Err(failed("the loopback redirect listener stopped accepting"));
                }
            }
        }
    }

    /// One accepted connection. `None` means it was not the redirect and the
    /// listener should keep waiting.
    fn serve(
        &self,
        mut stream: TcpStream,
        state: &str,
    ) -> Option<Result<Zeroizing<String>, SignError>> {
        let head = read_head(&mut stream)?;
        let target = head.split_whitespace().nth(1).unwrap_or_default();
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if path != self.path {
            respond(&mut stream, "404 Not Found", "Not this listener's path.");
            return None;
        }
        let parameters = parameters(query);
        let value = |name: &str| {
            parameters
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        if let Some(error) = value("error") {
            respond(&mut stream, "400 Bad Request", "Authorization refused.");
            // The authorization server's own error identifier, bounded and
            // stripped the way every value taken from a peer is. Its
            // `error_description` is free text and is never printed.
            return Some(Err(failed(format!(
                "the authorization server refused the round ({})",
                openszigno_core::sanitize_display(&error, 120)
            ))));
        }
        if value("state").as_deref() != Some(state) {
            respond(&mut stream, "400 Bad Request", "State mismatch.");
            return Some(Err(SignError::remote(
                SignErrorCode::CscStateMismatch,
                "the redirect carried a state this run did not issue; the authorization code was discarded unused",
            )));
        }
        let Some(code) = value("code").filter(|code| !code.is_empty()) else {
            respond(&mut stream, "400 Bad Request", "No authorization code.");
            return Some(Err(failed("the redirect carried no authorization code")));
        };
        respond(
            &mut stream,
            "200 OK",
            "openSzigno received the authorization. You can close this window.",
        );
        Some(Ok(Zeroizing::new(code)))
    }
}

/// The port and path of a configured loopback `redirect_uri`. The value has
/// already been checked to be a loopback URI when the configuration loaded.
fn split(uri: &str) -> (u16, String) {
    let rest = uri.strip_prefix("http://").unwrap_or(uri);
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let port = authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or(0);
    let path = format!("/{}", path.split(['?', '#']).next().unwrap_or_default());
    (
        port,
        if path == "/" {
            DEFAULT_REDIRECT_PATH.to_owned()
        } else {
            path
        },
    )
}

/// The `key=value` pairs of a query string, percent-decoded.
fn parameters(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key), decode(value))
        })
        .collect()
}

/// Read one request head, bounded. `None` when nothing usable arrived.
fn read_head(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut request: Vec<u8> = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            return Some(String::from_utf8_lossy(&request[..index]).into_owned());
        }
        if request.len() > MAX_REQUEST_BYTES {
            return None;
        }
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return None,
            Ok(read) => request.extend_from_slice(&buffer[..read]),
        }
    }
}

/// Answer the browser in plain text. Nothing about the run reaches the page:
/// the browser is somebody's ordinary browser, and a page that echoed a code
/// or a token would put it in a history entry.
///
/// The write side is shut down explicitly once the answer is out, before the
/// stream is dropped. That is what makes the answer *arrive*: the listener
/// stops the moment it has served the redirect, so the socket is closed a
/// microsecond later, and on a BSD-derived stack closing a socket that still
/// holds unread inbound data sends an RST that discards whatever is still in
/// the send buffer. An explicit `shutdown` sends a FIN first, which is the
/// end-of-response marker a `Connection: close` answer relies on.
fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;
