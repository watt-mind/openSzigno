//! Shared plumbing for the `--online` suites: a tiny loopback HTTP server, a
//! synthetic PKI whose certificates name it, and the helpers that run the CLI
//! against both.
//!
//! Every request in either suite goes to a `std::net::TcpListener` bound to
//! `127.0.0.1` on a port the operating system picked, and every certificate
//! that names it was minted seconds earlier by the synthetic PKI. Nothing here
//! reaches the internet, and no real CA, CRL distribution point or OCSP
//! responder is contacted or named.
//!
//! Each test binary compiles this module for itself and uses part of it, so
//! unused items are expected rather than a smell.
#![allow(dead_code)]

#[path = "../../../openszigno-verify/tests/common/mod.rs"]
pub mod common;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    CertSpec, CrlSpec, DossierSpec, OcspSpec, OcspStatus, SigningCertificateSpec, TestKey,
    authority_info_access_extension, build, build_crl, build_ocsp,
    crl_distribution_point_extension, document_signature, issued_by, keys, rsa_key, self_signed,
};
use rcgen::BasicConstraints;
use serde_json::Value;

pub const AT: &str = "2020-06-02T00:00:00Z";

// ---------------------------------------------------------------------------
// A very small HTTP server
// ---------------------------------------------------------------------------

/// A handler that computes a response body from a request body.
pub type Responder = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// What the server should answer with.
#[derive(Clone)]
pub enum Reply {
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
    /// A `200` whose body is computed from the request body.
    ///
    /// A timestamp authority cannot answer from a fixed script: the token it
    /// returns has to stamp the imprint the request asked about, and the
    /// request only exists once the signature does.
    Computed(Responder),
}

/// What the server saw, so a test can assert on the request as well as on the
/// answer. The OCSP `POST` is the only request in this suite with a body, and
/// it is the one that behaved differently on Windows, so it is worth being
/// able to say exactly what arrived.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    /// How many `Content-Length` headers the request carried. Two would mean
    /// the client set one that the transport also set, which is malformed.
    pub content_length_headers: usize,
    /// The value of that header.
    pub declared_length: Option<usize>,
    /// How many body bytes actually arrived.
    pub body_length: usize,
    /// The body itself. An OCSP `POST` is a question about one certificate,
    /// and two certificates behind one responder must ask two different ones.
    pub body: Vec<u8>,
    /// Whether the request announced a chunked body.
    pub chunked: bool,
}

pub struct Server {
    pub address: SocketAddr,
    pub stop: Arc<AtomicBool>,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    pub fn seen(&self) -> Vec<Seen> {
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
pub fn handle(stream: &mut TcpStream, routes: &[(&'static str, Reply)], seen: &Mutex<Vec<Seen>>) {
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
        body: body.clone(),
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
        Reply::Computed(answer) => {
            let payload = answer(&body);
            let ok = respond(
                stream,
                200,
                &[("content-type", "application/timestamp-reply")],
                payload.len(),
            ) && stream.write_all(&payload).is_ok();
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
pub fn respond(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(&str, &str)],
    length: usize,
) -> bool {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {length}\r\nConnection: close\r\n\r\n"
    ));
    stream.write_all(head.as_bytes()).is_ok()
}

pub const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        302 => "Found",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Nope",
    }
}

/// How many times a header appears in a request head.
pub fn header_count(head: &str, name: &str) -> usize {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .count()
}

/// One header value out of a request head, matched case-insensitively.
pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

// ---------------------------------------------------------------------------
// The synthetic PKI and dossier
// ---------------------------------------------------------------------------

pub struct Pki {
    pub root_der: Vec<u8>,
    pub signer_der: Vec<u8>,
    pub signer_key: TestKey,
    /// A second root, so a CRL can be built that no one in the chain issued.
    pub other_root_der: Vec<u8>,
}

/// A root and a signer, the signer publishing whichever URLs the test wants.
pub fn pki(crl_url: Option<&str>, ocsp_url: Option<&str>) -> Pki {
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

pub fn dossier(pki: &Pki) -> String {
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(pki.signer_der.clone()));
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    build(&spec, &[("doc", &pki.signer_key)])
}

pub fn good_crl(pki: &Pki) -> Vec<u8> {
    build_crl(&CrlSpec::new(
        pki.root_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    ))
}

/// A well-formed OCSP response about the signer, signed by a certificate no
/// model this build implements can authorise: it is not the issuing CA, that
/// CA did not issue it, and it carries no `id-kp-OCSPSigning`.
pub fn unauthorised_ocsp(pki: &Pki) -> Vec<u8> {
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

pub fn good_ocsp(pki: &Pki) -> Vec<u8> {
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

pub fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("the test binary has a path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("openszigno")
}

pub fn run(arguments: &[&str]) -> Output {
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

pub fn scratch() -> tempfile::TempDir {
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory resolves");
    tempfile::tempdir_in(base).expect("a temporary directory is available")
}

pub fn write_all(directory: &Path, xml: &str, root_der: &[u8]) -> (PathBuf, PathBuf) {
    let dossier = directory.join("input.es3");
    std::fs::write(&dossier, xml).expect("the dossier is written");
    let store = directory.join("store");
    std::fs::create_dir_all(store.join("anchors")).expect("the anchors directory is created");
    std::fs::write(store.join("anchors/root.der"), root_der).expect("the anchor is written");
    (dossier, store)
}

pub fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout is exactly one JSON value")
}

/// The revocation source the report recorded for the end-entity certificate.
pub fn end_entity_source(report: &Value) -> Option<String> {
    report["data"]["signatures"][0]["chain"][0]["revocation"]["source"]
        .as_str()
        .map(str::to_owned)
}

pub fn checks(report: &Value) -> Vec<String> {
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

/// Run `verify --online` against a trust store, with the loopback listener
/// this suite serves from explicitly permitted.
///
/// `--online-allow-private` is on every one of these runs on purpose. The
/// destination policy refuses `127.0.0.1` by default — a URL out of a
/// certificate must not be able to point the verifier at the machine it runs
/// on — and a synthetic PKI has nowhere else to publish. The tests that hold
/// *that* rule honest are the ones below which deliberately leave the flag
/// off.
pub fn verify_online(dossier: &Path, store: &Path, extra: &[&str]) -> Value {
    let mut arguments = extra.to_vec();
    arguments.push("--online-allow-private");
    verify_with(dossier, Some(store), &arguments)
}

/// One `verify --online` run, with the trust store and the extra flags spelled
/// out. `store` is `None` for a run with no trust anchor configured at all.
pub fn verify_with(dossier: &Path, store: Option<&Path>, extra: &[&str]) -> Value {
    let mut arguments = vec![
        "verify",
        dossier.to_str().expect("a UTF-8 path"),
        "--json",
        "--at",
        AT,
    ];
    if let Some(store) = store {
        arguments.push("--trust-store");
        arguments.push(store.to_str().expect("a UTF-8 path"));
    }
    arguments.push("--online");
    arguments.extend_from_slice(extra);
    json(&run(&arguments))
}

// ---------------------------------------------------------------------------
// Fixture plumbing
// ---------------------------------------------------------------------------

/// The directory that owns every fixture file for one test, kept alive for as
/// long as the test needs it.
pub struct Fixture {
    pub _directory: tempfile::TempDir,
    pub server: Server,
}

/// Build a PKI whose signer names `crl_path` and `ocsp_path` on a freshly
/// bound loopback server, then start that server with the routes `routes`
/// returns.
///
/// The two-step dance exists because the port is not known until the listener
/// is bound, and the certificate has to name it: a real certificate names a
/// URL, and this suite refuses to special-case that away.
pub fn with_urls(
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
pub fn reserved() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port is available");
    let address = listener.local_addr().expect("the port is known");
    (listener, address)
}

/// Start serving on a listener that is already bound.
pub fn serve_on(
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
