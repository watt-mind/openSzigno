//! `--online`: fetching revocation data over HTTP, against a local server.
//!
//! Every request in this file goes to a `std::net::TcpListener` bound to
//! `127.0.0.1` on a port the operating system picked, and every certificate
//! that names it was minted seconds earlier by the synthetic PKI. Nothing here
//! reaches the internet, and no real CA, CRL distribution point or OCSP
//! responder is contacted or named.
//!
//! What is being held honest is the transport policy, because that is the part
//! `openszigno-verify` structurally cannot enforce: the size caps, the refusal
//! to follow a redirect to another host, the bounded timeout, and — most
//! important — that a fetched artefact is still judged by the offline rules
//! and is not believed merely because a server served it.

#[path = "../../openszigno-verify/tests/common/mod.rs"]
mod common;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    CertSpec, CrlSpec, DossierSpec, OcspSpec, OcspStatus, RevokedSpec, SigningCertificateSpec,
    TestKey, authority_info_access_extension, build, build_crl, build_ocsp,
    crl_distribution_point_extension, document_signature, issued_by, keys, rsa_key, self_signed,
};
use rcgen::BasicConstraints;
use serde_json::Value;

const AT: &str = "2020-06-02T00:00:00Z";

// ---------------------------------------------------------------------------
// A very small HTTP server
// ---------------------------------------------------------------------------

/// What the server should answer with.
#[derive(Clone)]
enum Reply {
    /// A `200` with this body.
    Body(Vec<u8>),
    /// A `200` whose body is this many zero bytes, to exercise the size cap.
    Bulk(usize),
    /// A `302` to this absolute URL.
    Redirect(String),
    /// A status with an empty body.
    Status(u16),
    /// Accept the connection and never answer, to exercise the timeout.
    Silence,
}

/// What the server saw, so a test can assert on the request as well as on the
/// answer. The OCSP `POST` is the only request in this suite with a body, and
/// it is the one that behaved differently on Windows, so it is worth being
/// able to say exactly what arrived.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    /// How many `Content-Length` headers the request carried. Two would mean
    /// the client set one that the transport also set, which is malformed.
    content_length_headers: usize,
    /// The value of that header.
    declared_length: Option<usize>,
    /// How many body bytes actually arrived.
    body_length: usize,
    /// Whether the request announced a chunked body.
    chunked: bool,
}

struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("the log is not poisoned").clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept loop so the thread can notice and exit.
        let _ = TcpStream::connect(self.address);
    }
}

/// Serve one connection.
///
/// The sequencing here is not incidental. A server that answers before it has
/// read the whole request body leaves unread bytes in the receive buffer, and
/// closing a socket in that state makes Windows send an RST rather than a FIN
/// — which the client sees as a connection reset partway through reading the
/// response, not as an HTTP answer. On Linux and macOS the same code appears
/// to work, so the bug only shows up on one target and only for the request
/// that has a body: the OCSP `POST`.
///
/// So: read the headers, read exactly `Content-Length` bytes of body, answer
/// with an explicit length and `Connection: close`, flush, drain whatever else
/// arrived, and only then shut the write side down.
fn handle(stream: &mut TcpStream, routes: &[(&'static str, Reply)], seen: &Mutex<Vec<Seen>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("the read timeout is set");
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .expect("the write timeout is set");

    // --- the request head ---------------------------------------------------
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
    let mut start = head.split_whitespace();
    let method = start.next().unwrap_or_default().to_owned();
    let path = start.next().unwrap_or_default().to_owned();

    // A client that asks permission before sending a body gets it. ureq does
    // not use `Expect: 100-continue` today, but a server that ignored one
    // would deadlock rather than fail, which is a worse way to find out.
    if header(&head, "expect").is_some_and(|value| value.eq_ignore_ascii_case("100-continue")) {
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        let _ = stream.flush();
    }

    // --- the request body, in full ------------------------------------------
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
    seen.lock().expect("the log is not poisoned").push(Seen {
        method,
        path: path.clone(),
        content_length_headers: header_count(&head, "content-length"),
        declared_length: header(&head, "content-length")
            .and_then(|value| value.trim().parse::<usize>().ok()),
        body_length: body.len(),
        chunked: header(&head, "transfer-encoding")
            .is_some_and(|value| value.to_ascii_lowercase().contains("chunked")),
    });

    // --- the response --------------------------------------------------------
    let reply = routes
        .iter()
        .find(|(route, _)| *route == path)
        .map(|(_, reply)| reply.clone())
        .unwrap_or(Reply::Status(404));
    match &reply {
        Reply::Body(payload) => {
            let ok = respond(
                stream,
                200,
                &[("content-type", "application/octet-stream")],
                payload.len(),
            ) && stream.write_all(payload).is_ok();
            let _ = ok;
        }
        Reply::Bulk(size) => {
            if respond(stream, 200, &[], *size) {
                let chunk = vec![0_u8; 64 * 1024];
                let mut written = 0;
                while written < *size {
                    let take = chunk.len().min(size - written);
                    // The client stops reading at its size cap, so a failed
                    // write here is the expected end of this exchange.
                    if stream.write_all(&chunk[..take]).is_err() {
                        break;
                    }
                    written += take;
                }
            }
        }
        Reply::Redirect(target) => {
            let _ = respond(stream, 302, &[("location", target.as_str())], 0);
        }
        Reply::Status(status) => {
            let _ = respond(stream, *status, &[], 0);
        }
        Reply::Silence => {
            // The request has been read in full, so the client is not blocked
            // writing; it is waiting for an answer that never comes, which is
            // what the timeout test needs.
            std::thread::sleep(Duration::from_secs(40));
            return;
        }
    }
    let _ = stream.flush();

    // Anything still in flight is read off before the socket is closed, so the
    // close is a FIN rather than an RST.
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

/// Write a status line and headers, always with an explicit `Content-Length`
/// and `Connection: close` so the client never has to guess where the response
/// ends or whether the connection may be reused.
fn respond(stream: &mut TcpStream, status: u16, headers: &[(&str, &str)], length: usize) -> bool {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {length}\r\nConnection: close\r\n\r\n"
    ));
    stream.write_all(head.as_bytes()).is_ok()
}

const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        302 => "Found",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Nope",
    }
}

/// How many times a header appears in a request head.
fn header_count(head: &str, name: &str) -> usize {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .count()
}

/// One header value out of a request head, matched case-insensitively.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

// ---------------------------------------------------------------------------
// The synthetic PKI and dossier
// ---------------------------------------------------------------------------

struct Pki {
    root_der: Vec<u8>,
    signer_der: Vec<u8>,
    signer_key: TestKey,
    /// A second root, so a CRL can be built that no one in the chain issued.
    other_root_der: Vec<u8>,
}

/// A root and a signer, the signer publishing whichever URLs the test wants.
fn pki(crl_url: Option<&str>, ocsp_url: Option<&str>) -> Pki {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let other_root_key = rsa_key(keys::SECOND_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let other_root = self_signed(
        &CertSpec::ca("openSzigno Other Root", BasicConstraints::Unconstrained),
        &other_root_key,
    );
    let mut signer_spec = CertSpec::signer("openSzigno Test Signer");
    if let Some(url) = crl_url {
        signer_spec
            .custom_extensions
            .push(crl_distribution_point_extension(url));
    }
    if let Some(url) = ocsp_url {
        signer_spec
            .custom_extensions
            .push(authority_info_access_extension(url));
    }
    let signer = issued_by(&signer_spec, &signer_key, &root, &root_key);
    Pki {
        root_der: root.der,
        signer_der: signer.der,
        signer_key,
        other_root_der: other_root.der,
    }
}

fn dossier(pki: &Pki) -> String {
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(pki.signer_der.clone()));
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    build(&spec, &[("doc", &pki.signer_key)])
}

fn good_crl(pki: &Pki) -> Vec<u8> {
    build_crl(&CrlSpec::new(
        pki.root_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    ))
}

/// A well-formed OCSP response about the signer, signed by a certificate no
/// model this build implements can authorise: it is not the issuing CA, that
/// CA did not issue it, and it carries no `id-kp-OCSPSigning`.
fn unauthorised_ocsp(pki: &Pki) -> Vec<u8> {
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::SECOND_RSA2048),
    );
    spec.responder_der = Some(pki.other_root_der.clone());
    spec.include_responder_certificate = true;
    spec.sha256_cert_id = true;
    build_ocsp(&spec)
}

fn good_ocsp(pki: &Pki) -> Vec<u8> {
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    // The CA answers for itself, so no delegated responder certificate has to
    // travel with the response.
    spec.include_responder_certificate = false;
    spec.status = OcspStatus::Good;
    build_ocsp(&spec)
}

// ---------------------------------------------------------------------------
// Running the CLI
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("the test binary has a path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("openszigno")
}

fn run(arguments: &[&str]) -> Output {
    Command::new(binary())
        .args(arguments)
        // A proxy in the environment must not be picked up, and the test
        // asserts that by setting one that would fail if it were.
        .env("HTTP_PROXY", "http://127.0.0.1:1/")
        .env("http_proxy", "http://127.0.0.1:1/")
        .env("ALL_PROXY", "http://127.0.0.1:1/")
        .output()
        .expect("the CLI runs")
}

fn scratch() -> tempfile::TempDir {
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory resolves");
    tempfile::tempdir_in(base).expect("a temporary directory is available")
}

fn write_all(directory: &Path, xml: &str, root_der: &[u8]) -> (PathBuf, PathBuf) {
    let dossier = directory.join("input.es3");
    std::fs::write(&dossier, xml).expect("the dossier is written");
    let store = directory.join("store");
    std::fs::create_dir_all(store.join("anchors")).expect("the anchors directory is created");
    std::fs::write(store.join("anchors/root.der"), root_der).expect("the anchor is written");
    (dossier, store)
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout is exactly one JSON value")
}

/// The revocation source the report recorded for the end-entity certificate.
fn end_entity_source(report: &Value) -> Option<String> {
    report["data"]["signatures"][0]["chain"][0]["revocation"]["source"]
        .as_str()
        .map(str::to_owned)
}

fn checks(report: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for list in [
        &report["data"]["checks"],
        &report["data"]["signatures"][0]["checks"],
    ] {
        for check in list.as_array().into_iter().flatten() {
            out.push(format!(
                "{}={}: {}",
                check["code"].as_str().unwrap_or_default(),
                check["status"].as_str().unwrap_or_default(),
                check["message"].as_str().unwrap_or_default()
            ));
        }
    }
    out
}

fn verify_online(dossier: &Path, store: &Path, extra: &[&str]) -> Value {
    let mut arguments = vec![
        "verify",
        dossier.to_str().expect("a UTF-8 path"),
        "--json",
        "--at",
        AT,
        "--trust-store",
        store.to_str().expect("a UTF-8 path"),
        "--online",
    ];
    arguments.extend_from_slice(extra);
    json(&run(&arguments))
}

// ---------------------------------------------------------------------------
// The happy paths
// ---------------------------------------------------------------------------

#[test]
fn a_crl_fetched_from_a_distribution_point_answers_the_certificate() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        vec![("/ca.crl", Reply::Body(good_crl(pki)))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        end_entity_source(&report).as_deref(),
        Some("online_crl"),
        "{:?}",
        checks(&report)
    );
    assert_eq!(
        report["data"]["policy"]["revocation"].as_str(),
        Some("online")
    );
    assert!(
        checks(&report)
            .iter()
            .any(|check| check.starts_with("revocation_ok=passed")),
        "{:?}",
        checks(&report)
    );
    // The policy check says, in so many words, what the run was allowed to do.
    assert!(
        checks(&report)
            .iter()
            .any(|check| check.starts_with("revocation_policy=info") && check.contains("--online")),
        "{:?}",
        checks(&report)
    );
}

#[test]
fn an_ocsp_response_fetched_from_an_aia_responder_answers_the_certificate() {
    let (_pki, dossier_path, store, _fixture) = with_urls(None, Some("/ocsp"), |pki| {
        vec![("/ocsp", Reply::Body(good_ocsp(pki)))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        end_entity_source(&report).as_deref(),
        Some("online_ocsp"),
        "{:?}",
        checks(&report)
    );
}

#[test]
fn the_online_cache_makes_a_later_offline_run_reproduce_the_answer() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        vec![("/ca.crl", Reply::Body(good_crl(pki)))]
    });
    let directory = dossier_path.parent().expect("a parent").to_owned();
    let cache = directory.join("cache");

    let online = verify_online(
        &dossier_path,
        &store,
        &["--online-cache", cache.to_str().expect("a UTF-8 path")],
    );
    assert_eq!(end_entity_source(&online).as_deref(), Some("online_crl"));
    assert!(
        cache.join("crls").is_dir(),
        "the cache holds a crls/ directory"
    );

    // The same run with no network at all, taking the cache as an ordinary
    // revocation store, reaches the same answer through `store_crl`.
    let offline = json(&run(&[
        "verify",
        dossier_path.to_str().expect("a UTF-8 path"),
        "--json",
        "--at",
        AT,
        "--trust-store",
        store.to_str().expect("a UTF-8 path"),
        "--revocation-store",
        cache.to_str().expect("a UTF-8 path"),
    ]));
    assert_eq!(end_entity_source(&offline).as_deref(), Some("store_crl"));
    assert_eq!(
        offline["data"]["policy"]["revocation"].as_str(),
        Some("offline")
    );
}

#[test]
fn nothing_is_fetched_for_a_certificate_the_offline_store_already_covers() {
    // The server answers `500` for everything. If the run fetched anyway the
    // report would carry a `http status 500` failure; it must not, because the
    // revocation store already answers for the certificate.
    let (pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![("/ca.crl", Reply::Status(500))]
    });
    let directory = dossier_path.parent().expect("a parent").to_owned();
    let offline_store = directory.join("revocation");
    std::fs::create_dir_all(offline_store.join("crls")).expect("the crls directory is created");
    std::fs::write(offline_store.join("crls/ca.crl"), good_crl(&pki)).expect("the CRL is written");

    let report = verify_online(
        &dossier_path,
        &store,
        &[
            "--revocation-store",
            offline_store.to_str().expect("a UTF-8 path"),
        ],
    );
    assert_eq!(end_entity_source(&report).as_deref(), Some("store_crl"));
    assert!(
        !checks(&report)
            .iter()
            .any(|check| check.contains("http status")),
        "no fetch was attempted: {:?}",
        checks(&report)
    );
}

/// The shape of the OCSP request itself, asserted at the server.
///
/// This is the regression guard for a Windows-only CI failure. The request
/// carries a body, and a body whose end the peer has to infer — a chunked
/// request, or one the server answers before reading — is exactly the shape
/// that behaves differently on different platforms: closing a socket with
/// unread received data makes Windows send an RST, which the client sees as a
/// transport error rather than as an HTTP answer. So the request must arrive
/// whole, with one `Content-Length` and no chunking, and the server must read
/// all of it before replying.
#[test]
fn the_ocsp_request_arrives_whole_with_a_declared_length() {
    let (_pki, dossier_path, store, fixture) = with_urls(None, Some("/ocsp"), |pki| {
        vec![("/ocsp", Reply::Body(good_ocsp(pki)))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(end_entity_source(&report).as_deref(), Some("online_ocsp"));

    let seen = fixture.server.seen();
    let request = seen
        .iter()
        .find(|request| request.path == "/ocsp")
        .expect("the responder was asked");
    assert_eq!(request.method, "POST");
    assert!(!request.chunked, "the request must not be chunked");
    assert_eq!(
        request.content_length_headers, 1,
        "exactly one Content-Length: {request:?}"
    );
    assert_eq!(
        request.declared_length,
        Some(request.body_length),
        "the whole body arrived and was read before the answer: {request:?}"
    );
    assert!(request.body_length > 0, "{request:?}");
    // A CRL fetch carries no body at all, and must not claim one.
    assert!(
        seen.iter()
            .filter(|request| request.method == "GET")
            .all(|request| request.body_length == 0),
        "{seen:?}"
    );
}

/// The case the corpus hit, end to end: the responder answers, its answer
/// cannot be authorised, and the CRL two tiers down has to be fetched anyway.
///
/// A run that stopped at "the server replied" would never fetch the CRL and
/// would leave the certificate uncovered, which is exactly what made 50 real
/// responses look like a dead end.
#[test]
fn an_unusable_ocsp_answer_does_not_stop_the_crl_from_being_fetched() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), Some("/ocsp"), |pki| {
        vec![
            ("/ocsp", Reply::Body(unauthorised_ocsp(pki))),
            ("/ca.crl", Reply::Body(good_crl(pki))),
        ]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        end_entity_source(&report).as_deref(),
        Some("online_crl"),
        "{:?}",
        checks(&report)
    );
    assert!(
        checks(&report)
            .iter()
            .any(|check| check.starts_with("revocation_ok=passed") && check.contains("refused")),
        "the refused answer stays visible: {:?}",
        checks(&report)
    );
}

// ---------------------------------------------------------------------------
// The transport policy
// ---------------------------------------------------------------------------

#[test]
fn a_body_over_the_size_cap_is_refused() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![("/ca.crl", Reply::Bulk(17 * 1024 * 1024))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    let checks = checks(&report);
    assert!(
        checks
            .iter()
            .any(|check| check.contains("too large") && check.contains("/ca.crl")),
        "{checks:?}"
    );
    assert_ne!(end_entity_source(&report).as_deref(), Some("online_crl"));
}

#[test]
fn a_redirect_to_another_host_is_refused() {
    // The redirect target is a different port on the same address, which the
    // policy counts as another host: the certificate named one endpoint.
    let (listener, address) = reserved();
    let other = serve_on(listener, address, vec![("/ca.crl", Reply::Status(500))]);
    let elsewhere = other.url("/ca.crl");
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, move |_| {
        vec![("/ca.crl", Reply::Redirect(elsewhere.clone()))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    let checks = checks(&report);
    assert!(
        checks.iter().any(|check| check.contains("redirect")),
        "{checks:?}"
    );
}

#[test]
fn a_server_that_never_answers_is_bounded_rather_than_hung() {
    let (_pki, dossier_path, store, _fixture) =
        with_urls(Some("/ca.crl"), None, |_| vec![("/ca.crl", Reply::Silence)]);

    let started = Instant::now();
    let report = verify_online(&dossier_path, &store, &[]);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(35),
        "the fetch was bounded, not hung: {elapsed:?}"
    );
    let checks = checks(&report);
    assert!(
        checks.iter().any(|check| check.contains("timeout")),
        "{checks:?}"
    );
}

/// A failed fetch is a fact about the network, not about a certificate, so it
/// is reported as `info` and decides nothing on its own. Whether the gap
/// mattered is answered by the chain that needed the data — here it did, and
/// the signature says so.
#[test]
fn a_failed_fetch_is_informational_and_the_chain_reports_the_gap() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![("/ca.crl", Reply::Status(503))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    let checks = checks(&report);
    assert!(
        checks
            .iter()
            .any(|check| check.starts_with("online_fetch_failed=info")
                && check.contains("http status 503")),
        "{checks:?}"
    );
    // The blocking is done once, in the right place: on the chain that is
    // short of data.
    assert!(
        checks
            .iter()
            .any(|check| check.starts_with("revocation_status_unknown=unknown")),
        "{checks:?}"
    );
    assert_eq!(report["data"]["verdict"].as_str(), Some("indeterminate"));
}

#[test]
fn an_http_error_is_reported_with_its_status() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![("/ca.crl", Reply::Status(404))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    let checks = checks(&report);
    assert!(
        checks.iter().any(|check| check.contains("http status 404")),
        "{checks:?}"
    );
}

// ---------------------------------------------------------------------------
// A fetched artefact is still judged offline
// ---------------------------------------------------------------------------

#[test]
fn a_crl_from_the_wrong_issuer_is_fetched_and_then_rejected() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        // A perfectly well-formed CRL, signed by a CA that issued nothing in
        // this chain. Serving it must change nothing.
        let crl = build_crl(&CrlSpec::new(
            pki.other_root_der.clone(),
            rsa_key(keys::SECOND_RSA2048),
        ));
        vec![("/ca.crl", Reply::Body(crl))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_ne!(end_entity_source(&report).as_deref(), Some("online_crl"));
    let checks = checks(&report);
    assert!(
        checks
            .iter()
            .any(|check| check.starts_with("revocation_status_unknown=unknown")),
        "{checks:?}"
    );
    assert_eq!(report["data"]["verdict"].as_str(), Some("indeterminate"));
}

#[test]
fn a_fetched_crl_that_revokes_the_certificate_is_believed() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        let crl = build_crl(
            &CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048))
                .revoking(RevokedSpec::new(&pki.signer_der, "2020-05-10T00:00:00Z")),
        );
        vec![("/ca.crl", Reply::Body(crl))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        report["data"]["signatures"][0]["chain"][0]["revocation"]["status"].as_str(),
        Some("revoked"),
        "{:?}",
        checks(&report)
    );
    assert_eq!(report["data"]["verdict"].as_str(), Some("invalid"));
}

#[test]
fn a_server_that_answers_with_something_that_is_not_a_crl_is_refused() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![(
            "/ca.crl",
            Reply::Body(b"<html>captive portal</html>".to_vec()),
        )]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    let checks = checks(&report);
    assert!(
        checks.iter().any(|check| check.contains("invalid")),
        "{checks:?}"
    );
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

#[test]
fn online_and_no_revocation_cannot_be_combined() {
    let directory = scratch();
    let (dossier_path, store) = write_all(directory.path(), &dossier(&pki(None, None)), &[]);
    let output = run(&[
        "verify",
        dossier_path.to_str().expect("a UTF-8 path"),
        "--json",
        "--trust-store",
        store.to_str().expect("a UTF-8 path"),
        "--online",
        "--no-revocation",
    ]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn an_unusable_online_proxy_is_reported_rather_than_ignored() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![("/ca.crl", Reply::Status(500))]
    });
    let output = run(&[
        "verify",
        dossier_path.to_str().expect("a UTF-8 path"),
        "--json",
        "--at",
        AT,
        "--trust-store",
        store.to_str().expect("a UTF-8 path"),
        "--online",
        "--online-proxy",
        "not a proxy",
    ]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn the_online_flags_require_online() {
    let directory = scratch();
    let (dossier_path, store) = write_all(directory.path(), &dossier(&pki(None, None)), &[]);
    for extra in [
        vec!["--online-cache", "/tmp/nowhere"],
        vec!["--online-proxy", "http://127.0.0.1:1/"],
    ] {
        let mut arguments = vec![
            "verify",
            dossier_path.to_str().expect("a UTF-8 path"),
            "--json",
            "--trust-store",
            store.to_str().expect("a UTF-8 path"),
        ];
        arguments.extend(extra);
        assert_eq!(run(&arguments).status.code(), Some(2));
    }
}

// ---------------------------------------------------------------------------
// Fixture plumbing
// ---------------------------------------------------------------------------

/// The directory that owns every fixture file for one test, kept alive for as
/// long as the test needs it.
struct Fixture {
    _directory: tempfile::TempDir,
    server: Server,
}

/// Build a PKI whose signer names `crl_path` and `ocsp_path` on a freshly
/// bound loopback server, then start that server with the routes `routes`
/// returns.
///
/// The two-step dance exists because the port is not known until the listener
/// is bound, and the certificate has to name it: a real certificate names a
/// URL, and this suite refuses to special-case that away.
fn with_urls(
    crl_path: Option<&'static str>,
    ocsp_path: Option<&'static str>,
    routes: impl FnOnce(&Pki) -> Vec<(&'static str, Reply)>,
) -> (Pki, PathBuf, PathBuf, Fixture) {
    let (listener, address) = reserved();
    let url = |path: &str| format!("http://{address}{path}");
    let pki = pki(crl_path.map(&url).as_deref(), ocsp_path.map(url).as_deref());
    let routes = routes(&pki);
    let server = serve_on(listener, address, routes);

    let directory = scratch();
    let (dossier_path, store) = write_all(directory.path(), &dossier(&pki), &pki.root_der);
    (
        pki,
        dossier_path,
        store,
        Fixture {
            _directory: directory,
            server,
        },
    )
}

/// A bound listener and the address it holds.
///
/// The listener is kept rather than closed and rebound: a certificate has to
/// name the port before the routes exist, and dropping the socket in between
/// would leave a window in which something else could take it — a flake that
/// would only ever appear on a busy CI machine.
fn reserved() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port is available");
    let address = listener.local_addr().expect("the port is known");
    (listener, address)
}

/// Start serving on a listener that is already bound.
fn serve_on(
    listener: TcpListener,
    address: SocketAddr,
    routes: Vec<(&'static str, Reply)>,
) -> Server {
    let stop = Arc::new(AtomicBool::new(false));
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
    let flag = Arc::clone(&stop);
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        // The accept loop lives as long as the `Server`, which every test
        // holds for its whole body: a listener closed while the client is
        // still talking is the other way to turn a fetch into a transport
        // error rather than into an HTTP answer.
        for stream in listener.incoming() {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut stream) = stream else { continue };
            let routes = routes.clone();
            let log = Arc::clone(&log);
            std::thread::spawn(move || handle(&mut stream, &routes, &log));
        }
    });
    Server {
        address,
        stop,
        seen,
    }
}
