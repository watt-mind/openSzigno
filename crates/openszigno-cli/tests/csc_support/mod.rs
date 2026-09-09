//! A loopback mock Cloud Signature Consortium service, in the three
//! personalities `docs/remote-signing.md` section 3.5 recorded from live
//! deployments.
//!
//! The point of three rather than one is discovery. PrimeSign and Cleverbase
//! disagree about `supportsRar` and about whether `supportedHashTypes` is a
//! keyword or an OID, and the EUDI reference deployment is a third answer
//! again, so a client that works against all three has exercised its discovery
//! logic instead of hard-coding one vendor's replies.
//!
//! Everything here is synthetic and local. The listener is bound to
//! `127.0.0.1` on a port the operating system picked, the keys are derived or
//! decoded when the test runs, and no private key is committed. Nothing
//! reaches the internet and no real QTSP is contacted or named.
//!
//! The mock signs in `explicit` mode, with `credentials/authorize` returning
//! Signature Activation Data for a PIN; in `oauth2` mode the Signature
//! Activation Data comes out of the authorization round instead, and the
//! service is its own authorization server: `/oauth2/authorize` answers a
//! redirect to the client's loopback listener and `/oauth2/token` redeems the
//! code. PKCE is verified rather than accepted, because a client that could
//! send any verifier would be a client whose PKCE was never tested.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use openszigno_verify::tsa::MessageImprint;

#[path = "../online_support/mod.rs"]
pub mod online_support;

use online_support::common::{
    CertSpec, Issued, SigningKey, TestKey, ecdsa_key, issued_by, keys, rsa_key,
};

/// Which live service a personality imitates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Flavour {
    /// The EUDI reference QTSP: `specs` 2.2.0.0, `supportsRar` true,
    /// `supportedHashTypes` the keyword `dtbsr`, ECDSA over P-256.
    Eudi,
    /// PrimeSign: `specs` 2.1.0.1, `supportsRar` true, `dtbsr`, RSASSA-PSS
    /// with a DER `signAlgoParams`.
    PrimeSign,
    /// Cleverbase: `specs` 2.2.0.0, `supportsRar` false, the hash type given
    /// as the SHA-256 OID, ECDSA. The deliberate opposite of PrimeSign on
    /// every discovery field.
    Cleverbase,
}

impl Flavour {
    const fn specs(self) -> &'static str {
        match self {
            Self::Eudi | Self::Cleverbase => "2.2.0.0",
            Self::PrimeSign => "2.1.0.1",
        }
    }

    const fn supports_rar(self) -> bool {
        !matches!(self, Self::Cleverbase)
    }

    const fn hash_types(self) -> &'static str {
        match self {
            Self::Cleverbase => r#"["2.16.840.1.101.3.4.2.1"]"#,
            _ => r#"["dtbsr"]"#,
        }
    }

    /// The `signAlgorithms` object, and the credential's own `key/algo` list.
    const fn algorithms(self) -> (&'static str, &'static str) {
        match self {
            Self::PrimeSign => (
                concat!(
                    r#"{"algos":["1.2.840.113549.1.1.10","1.2.840.10045.4.3.2"],"#,
                    r#""algoParams":["MCEwCwYJYIZIAWUDBAIBoRgwFgYJKoZIhvcNAQEIMAkGBSsOAwIaBQA=",""]}"#
                ),
                r#"["1.2.840.113549.1.1.10"]"#,
            ),
            _ => (
                r#"{"algos":["1.2.840.10045.2.1","1.2.840.10045.4.3.2"],"algoParams":[]}"#,
                r#"["1.2.840.10045.4.3.2"]"#,
            ),
        }
    }
}

/// How one mock service should behave.
#[derive(Clone, Debug)]
pub struct Mock {
    pub flavour: Flavour,
    /// `explicit` or `oauth2`. Only `explicit` can be completed here.
    pub auth_mode: &'static str,
    /// When set, `credentials/authorize` refuses unless this PIN arrives.
    pub require_pin: Option<String>,
    /// Answer `signatures/signHash` with a signature over other bytes, which
    /// is what a broken or hostile service looks like from the client.
    pub wrong_signature: bool,
    /// What `credentials/list` reports. One is the ordinary case; two is
    /// `csc_credential_ambiguous`.
    pub credential_ids: Vec<String>,
    /// When set, `info` answers `302` with this `Location` instead of the
    /// discovery document. A redirect is the peer's choice, and this is how a
    /// hostile or misconfigured service asks the client to carry its bearer
    /// token somewhere else.
    pub redirect_info_to: Option<String>,
    /// Answer every token request with `invalid_grant`, which is what a wrong
    /// PKCE verifier or a replayed code looks like from the client.
    pub reject_token: bool,
    /// How long the access tokens this service issues last. `None` omits
    /// `expires_in` entirely, which is what a service that never says does.
    pub expires_in: Option<u64>,
    /// Whether a refresh token comes with them.
    pub issue_refresh_token: bool,
}

impl Mock {
    pub fn new(flavour: Flavour) -> Self {
        Self {
            flavour,
            auth_mode: "explicit",
            require_pin: None,
            wrong_signature: false,
            credential_ids: vec![CREDENTIAL.to_owned()],
            redirect_info_to: None,
            reject_token: false,
            expires_in: Some(3_600),
            issue_refresh_token: true,
        }
    }
}

/// The credential identifier every personality serves.
pub const CREDENTIAL: &str = "cred-1a2b3c";

fn base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The signing material behind one mock service: a key, the certificate the
/// test PKI issued for it, and the issuing root.
pub struct Material {
    pub key: TestKey,
    pub certificate: Vec<u8>,
    pub root: Vec<u8>,
}

/// Mint a credential the test PKI's root issued.
///
/// The key type follows the personality, because that is what makes the
/// algorithm mapping do real work: an EC credential is signed under ECDSA and
/// an RSA one under RSASSA-PSS, and the client has to pick each from the
/// credential's own `key/algo` list rather than from a vendor profile.
pub fn material(flavour: Flavour, root: &Issued, root_key: &TestKey) -> Material {
    let key = match flavour {
        Flavour::PrimeSign => rsa_key(keys::SIGNER_RSA2048),
        _ => ecdsa_key(7),
    };
    let certificate = issued_by(
        &CertSpec::signer("openSzigno CSC Test Signer"),
        &key,
        root,
        root_key,
    );
    Material {
        key,
        certificate: certificate.der,
        root: root.der.clone(),
    }
}

/// A running mock service.
pub struct Service {
    pub address: SocketAddr,
    stop: Arc<AtomicBool>,
    /// Every `Authorization` header value the service saw, so a test can
    /// assert the token arrived in the header and only there.
    seen_authorization: Arc<Mutex<Vec<String>>>,
    /// Every request path, in order, so a test can assert the sequence.
    seen_paths: Arc<Mutex<Vec<String>>>,
    /// The query string of every `/oauth2/authorize` request, so a test can
    /// assert what the client asked for: PKCE, the state, the scope, and the
    /// credential parameters in whichever form the personality takes.
    seen_authorize: Arc<Mutex<Vec<String>>>,
    /// The body of every `/oauth2/token` request, for the same reason.
    seen_token_requests: Arc<Mutex<Vec<String>>>,
}

impl Service {
    pub fn base_url(&self) -> String {
        format!("http://{}/csc/v2", self.address)
    }

    pub fn authorizations(&self) -> Vec<String> {
        self.seen_authorization
            .lock()
            .expect("the log is not poisoned")
            .clone()
    }

    pub fn paths(&self) -> Vec<String> {
        self.seen_paths
            .lock()
            .expect("the log is not poisoned")
            .clone()
    }

    pub fn authorize_queries(&self) -> Vec<String> {
        self.seen_authorize
            .lock()
            .expect("the log is not poisoned")
            .clone()
    }

    pub fn token_requests(&self) -> Vec<String> {
        self.seen_token_requests
            .lock()
            .expect("the log is not poisoned")
            .clone()
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
    }
}

/// Start a mock service on a freshly bound loopback port.
pub fn serve(mock: Mock, material: Material) -> Service {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port is available");
    let address = listener.local_addr().expect("the port is known");
    let stop = Arc::new(AtomicBool::new(false));
    let logs = Logs::default();
    let flag = Arc::clone(&stop);
    let shared = logs.clone();
    let state = Arc::new(State {
        mock,
        material,
        address,
        issued: Mutex::new(HashMap::new()),
        refresh_tokens: Mutex::new(HashMap::new()),
    });
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut stream) = stream else { continue };
            let state = Arc::clone(&state);
            let logs = shared.clone();
            std::thread::spawn(move || {
                handle(&mut stream, &state, &logs);
            });
        }
    });
    Service {
        address,
        stop,
        seen_authorization: logs.authorization,
        seen_paths: logs.paths,
        seen_authorize: logs.authorize,
        seen_token_requests: logs.token_requests,
    }
}

/// Everything the service records, shared with the threads that answer.
#[derive(Clone, Default)]
struct Logs {
    authorization: Arc<Mutex<Vec<String>>>,
    paths: Arc<Mutex<Vec<String>>>,
    authorize: Arc<Mutex<Vec<String>>>,
    token_requests: Arc<Mutex<Vec<String>>>,
}

impl Logs {
    fn push(log: &Mutex<Vec<String>>, value: String) {
        log.lock().expect("the log is not poisoned").push(value);
    }
}

/// One authorization code the service has issued and not yet redeemed.
struct Pending {
    challenge: String,
    redirect_uri: String,
    /// The Signature Activation Data the credential round's token will be,
    /// which is the hash the round was bound to. `None` for `scope=service`.
    sad: Option<String>,
}

struct State {
    mock: Mock,
    material: Material,
    address: SocketAddr,
    /// Authorization codes awaiting redemption, by code.
    issued: Mutex<HashMap<String, Pending>>,
    /// Refresh tokens this service has handed out, by token.
    refresh_tokens: Mutex<HashMap<String, ()>>,
}

/// One request, answered.
fn handle(stream: &mut TcpStream, state: &State, logs: &Logs) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("the read timeout is set");
    let mut request: Vec<u8> = Vec::new();
    let mut buffer = [0_u8; 1024];
    let head_end = loop {
        if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => request.extend_from_slice(&buffer[..read]),
        }
    };
    let head = String::from_utf8_lossy(&request[..head_end]).to_string();
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    if let Some(value) = header(&head, "authorization") {
        Logs::push(&logs.authorization, value.to_owned());
    }
    // The query string is part of an authorization request and no part of a
    // CSC operation, so the path log keeps the operation and the authorize log
    // keeps the parameters.
    Logs::push(
        &logs.paths,
        path.split('?').next().unwrap_or_default().to_owned(),
    );

    let declared = header(&head, "content-length")
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = request[head_end..].to_vec();
    while body.len() < declared {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => body.extend_from_slice(&buffer[..read]),
        }
    }

    let (status, payload) = answer(state, &path, &body, logs);
    let location = match (status, &state.mock.redirect_info_to) {
        (302, Some(target)) => format!("Location: {target}\r\n"),
        // An authorization redirect names its target in the body, which is
        // where the redirect half of this mock puts it.
        (302, None) => format!("Location: {payload}\r\n"),
        _ => String::new(),
    };
    let payload = if status == 302 && state.mock.redirect_info_to.is_none() {
        String::new()
    } else {
        payload
    };
    let head = format!(
        "HTTP/1.1 {status} {}\r\n{location}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        match status {
            200 => "OK",
            302 => "Found",
            _ => "Bad Request",
        },
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(payload.as_bytes());
    let _ = stream.flush();
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut drained = 0_usize;
    while drained < 64 * 1024 {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => drained += read,
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

/// The body one operation answers with.
fn answer(state: &State, path: &str, body: &[u8], logs: &Logs) -> (u16, String) {
    let mock = &state.mock;
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    if route == "/oauth2/authorize" {
        Logs::push(&logs.authorize, query.to_owned());
        return authorize_round(state, query);
    }
    if route == "/oauth2/token" {
        let form = String::from_utf8_lossy(body).into_owned();
        Logs::push(&logs.token_requests, form.clone());
        return token(state, &form);
    }
    // The operation is the whole suffix, not the last segment: `info` and
    // `credentials/info` end in the same word and are different operations.
    match route.strip_prefix("/csc/v2/").unwrap_or_default() {
        "info" if mock.redirect_info_to.is_some() => (302, String::new()),
        "info" => (200, info_body(state)),
        "credentials/list" => (
            200,
            format!(
                r#"{{"credentialIDs":[{}]}}"#,
                mock.credential_ids
                    .iter()
                    .map(|id| format!("\"{id}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
        "credentials/info" => (200, credential_body(state)),
        "credentials/authorize" => authorize(mock, body),
        "signatures/signHash" => sign_hash(state, body),
        _ => (404, r#"{"error":"unknown_operation"}"#.to_owned()),
    }
}

fn info_body(state: &State) -> String {
    let mock = &state.mock;
    let (algorithms, _) = mock.flavour.algorithms();
    format!(
        concat!(
            r#"{{"specs":"{}","name":"openSzigno mock CSC service","region":"EU","#,
            r#""authType":["oauth2code"],"oauth2":"http://{}","#,
            r#""methods":["credentials/list","credentials/info","credentials/authorize","signatures/signHash"],"#,
            r#""signAlgorithms":{},"supportsRar":{},"supportedHashTypes":{}}}"#
        ),
        mock.flavour.specs(),
        state.address,
        algorithms,
        mock.flavour.supports_rar(),
        mock.flavour.hash_types()
    )
}

/// `GET /oauth2/authorize`: the consent screen a person would see, answered
/// as the redirect that screen ends in.
///
/// Everything the client is required to send is checked rather than assumed:
/// the response type, PKCE with `S256`, a state, and a loopback redirect. The
/// code is bound to the challenge, so only the client that started the round
/// can redeem it.
fn authorize_round(state: &State, query: &str) -> (u16, String) {
    let parameters = form(query);
    let value = |name: &str| parameters.get(name).cloned().unwrap_or_default();
    if value("response_type") != "code"
        || value("code_challenge_method") != "S256"
        || value("code_challenge").is_empty()
        || value("state").is_empty()
    {
        return (400, r#"{"error":"invalid_request"}"#.to_owned());
    }
    let redirect_uri = value("redirect_uri");
    if !redirect_uri.starts_with("http://127.0.0.1:") {
        return (400, r#"{"error":"invalid_request"}"#.to_owned());
    }
    // A credential round names the hash it authorises, in one of the two forms
    // the surveyed services take. The token issued for it *is* the Signature
    // Activation Data, so it is bound to that hash here.
    let sad = if value("scope") == "credential" {
        let hash = if let Some(details) = parameters.get("authorization_details") {
            let parsed: serde_json::Value =
                serde_json::from_str(details).expect("the client sent JSON authorization_details");
            parsed[0]["documentDigests"][0]["hash"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        } else {
            value("hashes")
        };
        if hash.is_empty()
            || value("credentialID").is_empty() && !parameters.contains_key("authorization_details")
        {
            return (400, r#"{"error":"invalid_request"}"#.to_owned());
        }
        Some(format!("sad::{hash}"))
    } else {
        None
    };
    let code = format!("code-{}", state.issued.lock().expect("not poisoned").len());
    state.issued.lock().expect("not poisoned").insert(
        code.clone(),
        Pending {
            challenge: value("code_challenge"),
            redirect_uri: redirect_uri.clone(),
            sad,
        },
    );
    // The body carries the redirect target; `handle` turns it into the header.
    (
        302,
        format!(
            "{redirect_uri}?code={code}&state={}",
            value("state").replace('&', "")
        ),
    )
}

/// `POST /oauth2/token`: the authorization-code and refresh-token grants.
fn token(state: &State, body: &str) -> (u16, String) {
    if state.mock.reject_token {
        return (400, r#"{"error":"invalid_grant"}"#.to_owned());
    }
    let parameters = form(body);
    let value = |name: &str| parameters.get(name).cloned().unwrap_or_default();
    let sad = match value("grant_type").as_str() {
        "authorization_code" => {
            let Some(pending) = state
                .issued
                .lock()
                .expect("not poisoned")
                .remove(&value("code"))
            else {
                return (400, r#"{"error":"invalid_grant"}"#.to_owned());
            };
            // RFC 7636 section 4.6: the verifier is checked against the
            // challenge, and a code with the wrong one buys nothing.
            if s256(&value("code_verifier")) != pending.challenge
                || value("redirect_uri") != pending.redirect_uri
            {
                return (400, r#"{"error":"invalid_grant"}"#.to_owned());
            }
            pending.sad
        }
        "refresh_token" => {
            if !state
                .refresh_tokens
                .lock()
                .expect("not poisoned")
                .contains_key(&value("refresh_token"))
            {
                return (400, r#"{"error":"invalid_grant"}"#.to_owned());
            }
            None
        }
        _ => return (400, r#"{"error":"unsupported_grant_type"}"#.to_owned()),
    };
    let access_token = sad.unwrap_or_else(|| {
        format!(
            "synthetic-service-token-{}",
            state.refresh_tokens.lock().expect("not poisoned").len()
        )
    });
    let mut fields = vec![
        format!(r#""access_token":"{access_token}""#),
        r#""token_type":"Bearer""#.to_owned(),
    ];
    if let Some(seconds) = state.mock.expires_in {
        fields.push(format!(r#""expires_in":{seconds}"#));
    }
    if state.mock.issue_refresh_token {
        let refresh = format!(
            "synthetic-refresh-token-{}",
            state.refresh_tokens.lock().expect("not poisoned").len()
        );
        state
            .refresh_tokens
            .lock()
            .expect("not poisoned")
            .insert(refresh.clone(), ());
        fields.push(format!(r#""refresh_token":"{refresh}""#));
    }
    (200, format!("{{{}}}", fields.join(",")))
}

/// The base64url of the SHA-256 of a PKCE verifier, unpadded.
fn s256(verifier: &str) -> String {
    use sha2::Digest as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier))
}

/// A `key=value&...` string, percent-decoded.
pub fn form(text: &str) -> HashMap<String, String> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
}

/// Percent-decoding, `+` as a space, for the query and form parsers above.
pub fn percent_decode(value: &str) -> String {
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

fn credential_body(state: &State) -> String {
    let (_, key_algorithms) = state.mock.flavour.algorithms();
    format!(
        concat!(
            r#"{{"key":{{"status":"enabled","algo":{},"len":256}},"#,
            r#""cert":{{"status":"valid","certificates":["{}","{}"],"#,
            r#""subjectDN":"CN=openSzigno CSC Test Signer"}},"#,
            r#""authMode":"{}","SCAL":"2","multisign":1,"lang":"en"}}"#
        ),
        key_algorithms,
        base64(&state.material.certificate),
        base64(&state.material.root),
        state.mock.auth_mode
    )
}

/// `credentials/authorize`: a SAD, and only for the right PIN.
fn authorize(mock: &Mock, body: &[u8]) -> (u16, String) {
    let request: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, r#"{"error":"invalid_request"}"#.to_owned()),
    };
    if request["numSignatures"] != serde_json::json!(1) {
        return (400, r#"{"error":"invalid_request"}"#.to_owned());
    }
    if request["hashes"].as_array().map_or(0, Vec::len) != 1 {
        return (400, r#"{"error":"invalid_request"}"#.to_owned());
    }
    if let Some(expected) = &mock.require_pin
        && request["PIN"].as_str() != Some(expected.as_str())
    {
        return (400, r#"{"error":"invalid_pin"}"#.to_owned());
    }
    // The SAD names the hash it authorises, so `signatures/signHash` can
    // refuse to sign anything else. A real service does the same thing with a
    // token it can check; this one does it with a string it can compare.
    let hash = request["hashes"][0].as_str().unwrap_or_default();
    (200, format!(r#"{{"SAD":"sad::{hash}","expiresIn":300}}"#))
}

/// `signatures/signHash`: the signature over the digest that was authorised.
fn sign_hash(state: &State, body: &[u8]) -> (u16, String) {
    let request: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, r#"{"error":"invalid_request"}"#.to_owned()),
    };
    let hash = request["hashes"][0].as_str().unwrap_or_default();
    if request["SAD"].as_str() != Some(&format!("sad::{hash}")) {
        // A SAD bound to another hash authorises nothing here.
        return (400, r#"{"error":"invalid_sad"}"#.to_owned());
    }
    let Ok(digest) = base64::engine::general_purpose::STANDARD.decode(hash) else {
        return (400, r#"{"error":"invalid_request"}"#.to_owned());
    };
    let digest = if state.mock.wrong_signature {
        // A perfectly formed signature over the wrong bytes: exactly what a
        // canonicalization mistake, or a hostile service, produces.
        use sha2::Digest as _;
        sha2::Sha256::digest(b"not the digest that was sent").to_vec()
    } else {
        digest
    };
    (
        200,
        format!(r#"{{"signatures":["{}"]}}"#, base64(&sign(state, &digest))),
    )
}

/// Sign a digest with the credential's key, in the scheme its personality
/// advertises.
fn sign(state: &State, digest: &[u8]) -> Vec<u8> {
    match (&state.material.key.signing, state.mock.flavour) {
        (SigningKey::Rsa(private), Flavour::PrimeSign) => {
            use rsa::signature::{SignatureEncoding as _, hazmat::RandomizedPrehashSigner as _};
            rsa::pss::SigningKey::<sha2::Sha256>::new((**private).clone())
                .sign_prehash_with_rng(&mut rsa::rand_core::OsRng, digest)
                .expect("prehash signing works")
                .to_vec()
        }
        (SigningKey::Rsa(private), _) => {
            use rsa::signature::{SignatureEncoding as _, hazmat::PrehashSigner as _};
            rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new((**private).clone())
                .sign_prehash(digest)
                .expect("prehash signing works")
                .to_vec()
        }
        (SigningKey::EcdsaP256(private), _) => {
            use p256::ecdsa::signature::hazmat::PrehashSigner as _;
            let signature: p256::ecdsa::Signature =
                private.sign_prehash(digest).expect("prehash signing works");
            // The DER form, deliberately: services disagree about which of the
            // two encodings they return, and the client converts.
            signature.to_der().as_bytes().to_vec()
        }
        _ => panic!("this mock has no key it can sign with"),
    }
}

/// One header value out of a request head, matched case-insensitively.
pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

/// The `messageImprint` of an RFC 3161 request, as the loopback timestamp
/// authority reads it.
#[derive(der::Sequence)]
pub struct TimeStampReq {
    pub version: i32,
    pub message_imprint: MessageImprint,
    pub cert_req: bool,
}
