//! `sign`, end to end: what this tool writes is what this tool verifies.
//!
//! Every run here creates a dossier, signs it, and then verifies it against a
//! trust store the test built seconds earlier. That last step is the whole
//! point of the suite, and it is worth being exact about what it proves: a
//! `valid` verdict over a synthetic chain means the signature verified against
//! the anchor *this test chose to trust*, and nothing more. It is a statement
//! about the shape of what `sign` writes, never about anybody's identity.
//!
//! The RSA keys are the committed synthetic ones the whole test suite shares
//! (`crates/openszigno-verify/tests/common/keys.rs`); the P-256 key is
//! generated while the test runs. No key this suite uses is created by it and
//! left behind, and none is ever written outside a temporary directory.

mod online_support;

use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;

use base64::Engine as _;
use online_support::common::{
    CertSpec, CrlSpec, TestKey, TimestampSpec, build_crl, build_timestamp_token_for_imprint,
    extended_key_usage_extension, issued_by, keys, rsa_key, self_signed,
};
use online_support::{Reply, json, reserved, run, scratch, serve_on};
use rcgen::BasicConstraints;
use serde_json::Value;

/// The instant every run is judged at: inside the synthetic certificates'
/// validity and inside the synthetic CRL's freshness window.
const AT: &str = "2020-06-02T00:00:00Z";
/// The `genTime` the loopback timestamp authority stamps with.
///
/// It is after the signing time on purpose. A token whose `genTime` precedes
/// the claimed `xades:SigningTime` by more than its accuracy makes the
/// verifier report `timestamp_before_signing_time`, which leaves the token
/// unverified and the signature indeterminate — the same thing that happens
/// to a real signature whose clock ran ahead of its authority's.
const GEN_TIME: &str = "2020-06-02T00:00:10Z";
/// RFC 3161 `id-kp-timeStamping`.
const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";

// ---------------------------------------------------------------------------
// The synthetic PKI, on disk
// ---------------------------------------------------------------------------

/// A root, a signer it issued, and a timestamp authority it issued.
struct Pki {
    root_der: Vec<u8>,
    signer_der: Vec<u8>,
    /// The signer's PKCS#8 private key, as `--key` takes it.
    signer_key_der: Vec<u8>,
    tsa_der: Vec<u8>,
    tsa_key: TestKey,
}

/// Decode one of the committed synthetic PKCS#8 keys.
fn pkcs8(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(
            text.chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>(),
        )
        .expect("the embedded key is Base64")
}

fn pki() -> Pki {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("openSzigno Test Signer"),
        &signer_key,
        &root,
        &root_key,
    );
    let mut tsa_spec = CertSpec::signer("openSzigno Test TSA");
    tsa_spec.custom_extensions = vec![extended_key_usage_extension(&[ID_KP_TIME_STAMPING], true)];
    let tsa = issued_by(&tsa_spec, &rsa_key(keys::THIRD_RSA2048), &root, &root_key);
    Pki {
        root_der: root.der,
        signer_der: signer.der,
        signer_key_der: pkcs8(keys::SIGNER_RSA2048),
        tsa_der: tsa.der,
        tsa_key: rsa_key(keys::THIRD_RSA2048),
    }
}

/// One test's working directory: an unsigned dossier, the signer's key and
/// certificate, and a trust store holding the root.
struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn text(&self, name: &str) -> String {
        self.path(name).to_str().expect("a UTF-8 path").to_owned()
    }
}

fn binary_run(arguments: &[&str]) -> Output {
    run(arguments)
}

/// Create an unsigned dossier with `documents` text documents.
fn create(fixture: &Fixture, documents: usize) {
    let mut arguments = vec![
        "create".to_owned(),
        "--output".to_owned(),
        fixture.text("input.es3"),
        "--title".to_owned(),
        "Synthetic signing fixture".to_owned(),
        "--created".to_owned(),
        "2020-05-02T00:00:00Z".to_owned(),
        "--json".to_owned(),
    ];
    for index in 0..documents {
        let path = fixture.path(&format!("note{index}.txt"));
        std::fs::write(&path, format!("document {index}\n")).expect("the input is written");
        arguments.push("--document".to_owned());
        arguments.push(format!(
            "{}::note{index}.txt",
            path.to_str().expect("a UTF-8 path")
        ));
    }
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let output = binary_run(&borrowed);
    assert!(output.status.success(), "create failed: {output:?}");
}

/// Lay out one test's directory, with the key material a signing run needs.
fn fixture(pki: &Pki, documents: usize) -> Fixture {
    let fixture = Fixture {
        directory: scratch(),
    };
    std::fs::write(fixture.path("signer.key"), &pki.signer_key_der).expect("the key is written");
    std::fs::write(fixture.path("signer.crt"), &pki.signer_der)
        .expect("the certificate is written");
    std::fs::write(fixture.path("root.crt"), &pki.root_der).expect("the root is written");
    let anchors = fixture.path("store/anchors");
    std::fs::create_dir_all(&anchors).expect("the anchors directory is created");
    std::fs::write(anchors.join("root.der"), &pki.root_der).expect("the anchor is written");
    create(&fixture, documents);
    fixture
}

/// A revocation store holding one CRL from the root, which answers for both
/// the signer's and the timestamp authority's certificates.
fn revocation_store(fixture: &Fixture, pki: &Pki) -> String {
    let directory = fixture.path("revocation/crls");
    std::fs::create_dir_all(&directory).expect("the crls directory is created");
    let crl = build_crl(&CrlSpec::new(
        pki.root_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    ));
    std::fs::write(directory.join("root.crl"), crl).expect("the CRL is written");
    fixture.text("revocation")
}

// ---------------------------------------------------------------------------
// The loopback timestamp authority
// ---------------------------------------------------------------------------

/// The `messageImprint` of an RFC 3161 request, as the responder reads it.
#[derive(der::Sequence)]
struct TimeStampReq {
    version: i32,
    message_imprint: openszigno_verify::tsa::MessageImprint,
    cert_req: bool,
}

/// A loopback timestamp authority: it reads the imprint out of the request and
/// stamps that, exactly as a real one does. It never sees the data.
fn timestamp_authority(pki: &Pki) -> (online_support::Server, String) {
    let (listener, address) = reserved();
    let tsa_der = pki.tsa_der.clone();
    let root_der = pki.root_der.clone();
    let tsa_key_source = || rsa_key(keys::THIRD_RSA2048);
    // The key is rebuilt inside the closure because a `TestKey` is not
    // clonable and the responder outlives this function.
    let _ = &pki.tsa_key;
    let answer = move |body: &[u8]| -> Vec<u8> {
        use der::{Decode as _, Encode as _};
        let request = TimeStampReq::from_der(body).expect("the CLI sent a TimeStampReq");
        let mut spec = TimestampSpec::new(tsa_key_source(), tsa_der.clone(), GEN_TIME);
        // The issuing CA travels in the token, so a verifier can build the
        // authority's path without being handed it separately.
        spec.token_certificates = vec![root_der.clone()];
        let token = build_timestamp_token_for_imprint(
            &spec,
            request.message_imprint.hashed_message.as_bytes(),
        );
        openszigno_verify::tsa::TimeStampResp {
            status: openszigno_verify::tsa::PkiStatusInfo {
                status: 0,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: Some(
                cms::content_info::ContentInfo::from_der(&token).expect("the token decodes"),
            ),
        }
        .to_der()
        .expect("the response encodes")
    };
    let server = serve_on(
        listener,
        address,
        vec![("/tsa", Reply::Computed(Arc::new(answer)))],
    );
    let url = format!("http://{address}/tsa");
    (server, url)
}

// ---------------------------------------------------------------------------
// Running and reading a report
// ---------------------------------------------------------------------------

fn sign(fixture: &Fixture, extra: &[&str]) -> Value {
    let mut arguments = vec![
        "sign",
        &fixture.text("input.es3"),
        "--output",
        &fixture.text("signed.es3"),
        "--key",
        &fixture.text("signer.key"),
        "--cert",
        &fixture.text("signer.crt"),
        "--signing-time",
        AT,
        "--json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<String>>();
    arguments.extend(extra.iter().map(|value| (*value).to_owned()));
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    json(&binary_run(&borrowed))
}

fn sign_output(fixture: &Fixture, extra: &[&str]) -> Output {
    sign_with(fixture, "signer.key", "signer.crt", extra)
}

/// One `sign` run with the key and certificate named explicitly, because
/// `clap` refuses a flag given twice and the refusal cases need to replace one
/// rather than add a second.
fn sign_with(fixture: &Fixture, key: &str, cert: &str, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "sign".to_owned(),
        fixture.text("input.es3"),
        "--output".to_owned(),
        fixture.text("signed.es3"),
        "--key".to_owned(),
        fixture.text(key),
        "--cert".to_owned(),
        fixture.text(cert),
        "--signing-time".to_owned(),
        AT.to_owned(),
        "--json".to_owned(),
    ];
    arguments.extend(extra.iter().map(|value| (*value).to_owned()));
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    binary_run(&borrowed)
}

fn verify(fixture: &Fixture, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "verify".to_owned(),
        fixture.text("signed.es3"),
        "--trust-store".to_owned(),
        fixture.text("store"),
        "--at".to_owned(),
        AT.to_owned(),
        "--json".to_owned(),
    ];
    arguments.extend(extra.iter().map(|value| (*value).to_owned()));
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    binary_run(&borrowed)
}

/// Every check in a report, as `code=status` strings.
fn checks(report: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for check in report["data"]["checks"].as_array().into_iter().flatten() {
        out.push(pair(check));
    }
    for signature in report["data"]["signatures"]
        .as_array()
        .into_iter()
        .flatten()
    {
        for check in signature["checks"].as_array().into_iter().flatten() {
            out.push(pair(check));
        }
    }
    out
}

fn pair(check: &Value) -> (String, String) {
    (
        check["code"].as_str().unwrap_or_default().to_owned(),
        check["status"].as_str().unwrap_or_default().to_owned(),
    )
}

/// The check codes that block a `valid` verdict: everything that is not
/// `passed` and not `info`.
fn blocking(report: &Value) -> Vec<String> {
    let mut codes: Vec<String> = checks(report)
        .into_iter()
        .filter(|(_, status)| status != "passed" && status != "info")
        .map(|(code, _)| code)
        .collect();
    codes.sort();
    codes.dedup();
    codes
}

fn assert_check(report: &Value, code: &str, status: &str) {
    assert!(
        checks(report).contains(&(code.to_owned(), status.to_owned())),
        "expected {code}={status}; got {:?}",
        checks(report)
    );
}

// ---------------------------------------------------------------------------
// 1. The acceptance path
// ---------------------------------------------------------------------------

#[test]
fn a_signed_dossier_without_a_timestamp_is_indeterminate_for_exactly_two_reasons() {
    let pki = pki();
    let fixture = fixture(&pki, 2);
    let signed = sign(&fixture, &[]);
    assert_eq!(signed["ok"], Value::Bool(true));
    assert_eq!(
        signed["data"]["signatures"]
            .as_array()
            .expect("an array")
            .len(),
        2
    );
    assert_eq!(signed["warnings"][0]["code"], "signed_dossier_unverified");

    let output = verify(&fixture, &[]);
    let report = json(&output);
    // Everything about the signature itself passed.
    for code in [
        "sig_structure",
        "sig_placement",
        "reference_scope_complete",
        "reference_digest_ok",
        "signature_value_ok",
        "xades_signing_certificate_bound",
        "cert_path_ok",
    ] {
        assert_check(&report, code, "passed");
    }
    // What is left open is exactly what this run supplied no evidence for: a
    // timestamp, and revocation data. Nothing else blocks.
    assert_eq!(
        blocking(&report),
        vec![
            "revocation_status_unknown".to_owned(),
            "signature_timestamp_absent".to_owned(),
        ]
    );
    // Every document is covered; the check is `info` rather than `passed`
    // because the covering signatures are themselves indeterminate here.
    assert_check(&report, "documents_all_covered", "info");
    assert_eq!(report["data"]["verdict"], "indeterminate");
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn a_timestamped_signature_with_revocation_data_verifies_as_valid() {
    let pki = pki();
    let fixture = fixture(&pki, 2);
    let (_authority, url) = timestamp_authority(&pki);
    let store = revocation_store(&fixture, &pki);

    let signed = sign(
        &fixture,
        &[
            "--tsa",
            &url,
            "--online-allow-private",
            "--chain",
            &fixture.text("root.crt"),
        ],
    );
    assert_eq!(signed["ok"], Value::Bool(true));
    assert!(
        signed["data"]["signatures"]
            .as_array()
            .expect("an array")
            .iter()
            .all(|signature| signature["timestamped"] == Value::Bool(true))
    );

    let output = verify(&fixture, &["--revocation-store", &store]);
    let report = json(&output);
    assert_eq!(
        blocking(&report),
        Vec::<String>::new(),
        "nothing may block: {:?}",
        checks(&report)
    );
    assert_check(&report, "timestamp_verified", "passed");
    assert_check(&report, "revocation_ok", "passed");
    assert_check(&report, "documents_all_covered", "passed");
    assert_eq!(report["data"]["verdict"], "valid");
    assert_eq!(output.status.code(), Some(0));
}

// ---------------------------------------------------------------------------
// 2. Scope
// ---------------------------------------------------------------------------

#[test]
fn a_dossier_scope_signature_covers_every_document() {
    let pki = pki();
    let fixture = fixture(&pki, 3);
    let signed = sign(&fixture, &["--scope", "dossier"]);
    let signatures = signed["data"]["signatures"].as_array().expect("an array");
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0]["scope"], "dossier");
    assert_eq!(signatures[0]["document_index"], Value::Null);

    let (_authority, url) = timestamp_authority(&pki);
    let store = revocation_store(&fixture, &pki);
    // A second run, timestamped, so the coverage state can reach `covered`
    // rather than `covered_unverified`.
    std::fs::remove_file(fixture.path("signed.es3")).expect("the first output is removed");
    sign(
        &fixture,
        &[
            "--scope",
            "dossier",
            "--tsa",
            &url,
            "--online-allow-private",
            "--chain",
            &fixture.text("root.crt"),
        ],
    );
    let report = json(&verify(&fixture, &["--revocation-store", &store]));
    let documents = report["data"]["documents"].as_array().expect("an array");
    assert_eq!(documents.len(), 3);
    assert!(
        documents
            .iter()
            .all(|document| document["coverage"] == "covered"),
        "every document is covered: {documents:?}"
    );
    assert_eq!(report["data"]["verdict"], "valid");
}

// ---------------------------------------------------------------------------
// 3. Algorithms
// ---------------------------------------------------------------------------

#[test]
fn an_rsa_pss_signature_verifies() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let signed = sign(&fixture, &["--algorithm", "rsa-pss-sha256"]);
    assert_eq!(
        signed["data"]["signatures"][0]["algorithm"],
        "rsa-pss-sha256"
    );
    let report = json(&verify(&fixture, &[]));
    assert_check(&report, "signature_value_ok", "passed");
    assert_check(&report, "signature_algorithm_allowed", "passed");
}

#[test]
fn an_ecdsa_p256_signature_verifies() {
    // The P-256 key is generated here rather than committed, and the
    // certificate is issued from it in the same breath.
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("a P-256 key is generated");
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("no SAN is valid");
    params.not_before = rcgen::date_time_ymd(2019, 1, 1);
    params.not_after = rcgen::date_time_ymd(2039, 1, 1);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::ContentCommitment,
    ];
    let issuer = rcgen::Issuer::from_params(
        &root.params,
        root_key.rcgen.as_ref().expect("the root key can issue"),
    );
    let signer = params
        .signed_by(&pair, &issuer)
        .expect("issuing succeeds")
        .der()
        .to_vec();

    let pki = Pki {
        root_der: root.der,
        signer_der: signer,
        signer_key_der: pair.serialize_der(),
        tsa_der: Vec::new(),
        tsa_key: rsa_key(keys::THIRD_RSA2048),
    };
    let fixture = fixture(&pki, 1);
    let signed = sign(&fixture, &[]);
    assert_eq!(
        signed["data"]["signatures"][0]["algorithm"],
        "ecdsa-p256-sha256"
    );
    let report = json(&verify(&fixture, &[]));
    assert_check(&report, "signature_value_ok", "passed");
    assert_check(&report, "cert_path_ok", "passed");
}

// ---------------------------------------------------------------------------
// 4. Refusals
// ---------------------------------------------------------------------------

#[test]
fn a_certificate_that_does_not_belong_to_the_key_is_a_mismatch() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let output = sign_with(&fixture, "signer.key", "root.crt", &[]);
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "signing_key_mismatch");
    assert_eq!(output.status.code(), Some(4));
    assert!(!fixture.path("signed.es3").exists());
}

#[test]
fn a_missing_key_file_is_an_io_error() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let output = sign_with(&fixture, "absent.key", "signer.crt", &[]);
    assert_eq!(json(&output)["errors"][0]["code"], "io_error");
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn a_refused_tsa_destination_is_a_tsa_failure_naming_the_rule() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let (_authority, url) = timestamp_authority(&pki);
    // No `--online-allow-private`: a loopback destination is refused before a
    // socket is opened, exactly as it is for `verify --online`.
    let output = sign_output(&fixture, &["--tsa", &url]);
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "tsa_failed");
    let message = report["errors"][0]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(
        message.contains("destination_refused"),
        "the reason names the rule: {message}"
    );
    assert_eq!(output.status.code(), Some(5));
    assert!(!fixture.path("signed.es3").exists());
}

#[test]
fn a_tsa_that_answers_with_rubbish_is_a_tsa_failure() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let (listener, address) = reserved();
    let _server = serve_on(
        listener,
        address,
        vec![(
            "/tsa",
            Reply::Body(b"<html>not a timestamp</html>".to_vec()),
        )],
    );
    let url = format!("http://{address}/tsa");
    let output = sign_output(&fixture, &["--tsa", &url, "--online-allow-private"]);
    assert_eq!(json(&output)["errors"][0]["code"], "tsa_failed");
    assert_eq!(output.status.code(), Some(5));
    assert!(!fixture.path("signed.es3").exists());
}

#[test]
fn an_existing_output_is_never_overwritten() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    std::fs::write(fixture.path("signed.es3"), b"already here").expect("the file is written");
    let output = sign_output(&fixture, &[]);
    assert_eq!(json(&output)["errors"][0]["code"], "output_exists");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        std::fs::read(fixture.path("signed.es3")).expect("still readable"),
        b"already here"
    );
}

#[test]
fn a_selector_that_matches_no_document_is_refused() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let output = sign_output(&fixture, &["--document", "#9"]);
    assert_eq!(json(&output)["errors"][0]["code"], "document_not_found");
    assert_eq!(output.status.code(), Some(4));
}

// ---------------------------------------------------------------------------
// 5. Nothing secret ever reaches the output
// ---------------------------------------------------------------------------

#[test]
fn no_key_material_or_passphrase_appears_in_any_output() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let passphrase = "correct horse battery staple";
    std::fs::write(fixture.path("pass"), passphrase).expect("the passphrase is written");

    // A successful run, a mismatch, and an unreadable key: three shapes, one
    // rule.
    let mut outputs = vec![sign_output(
        &fixture,
        &["--passphrase-file", &fixture.text("pass")],
    )];
    std::fs::remove_file(fixture.path("signed.es3")).expect("the output is removed");
    outputs.push(sign_with(&fixture, "signer.key", "root.crt", &[]));
    std::fs::write(fixture.path("broken.key"), b"not a key at all").expect("written");
    outputs.push(sign_with(&fixture, "broken.key", "signer.crt", &[]));

    let key_fragment = base64::engine::general_purpose::STANDARD.encode(&pki.signer_key_der[..48]);
    for output in &outputs {
        for stream in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(stream);
            assert!(
                !text.contains(passphrase),
                "a passphrase reached the output"
            );
            assert!(
                !text.contains(&key_fragment),
                "key bytes reached the output"
            );
            assert!(
                !text.contains("PRIVATE KEY"),
                "key armour reached the output"
            );
        }
    }
    // Nor does any of it reach the dossier that was written.
    let written = std::fs::read(fixture.path("signed.es3")).ok();
    if let Some(bytes) = written {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(passphrase));
        assert!(!text.contains(&key_fragment));
    }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn two_rsa_pkcs1_runs_over_the_same_inputs_write_the_same_bytes() {
    let pki = pki();
    let fixture = fixture(&pki, 2);
    sign(&fixture, &[]);
    let first = std::fs::read(fixture.path("signed.es3")).expect("the output exists");
    std::fs::remove_file(fixture.path("signed.es3")).expect("the output is removed");
    sign(&fixture, &[]);
    let second = std::fs::read(fixture.path("signed.es3")).expect("the output exists");
    assert_eq!(first, second);
}

// ---------------------------------------------------------------------------
// 8. The dossier's own text is never mistaken for the signer's scaffolding
// ---------------------------------------------------------------------------

/// A document title that reads exactly like one of the signer's internal
/// placeholders is content: it is signed, and it comes back out unchanged.
///
/// It used to be substituted along with the placeholder it resembled, after
/// the digest over it had been taken, so the run reported success and `verify`
/// then reported `reference_digest_mismatch`.
#[test]
fn a_title_that_reads_like_a_placeholder_is_signed_and_listed_unchanged() {
    let pki = pki();
    let fixture = fixture(&pki, 2);
    let titles = [
        "@@openszigno-digest:ref-sig-doc0-object@@".to_owned(),
        "@@openszigno-value:sig-doc0@@".to_owned(),
    ];
    let input = fixture.path("input.es3");
    let mut text = String::from_utf8(std::fs::read(&input).expect("the dossier is read"))
        .expect("it is UTF-8");
    for (index, title) in titles.iter().enumerate() {
        text = text.replace(&format!("note{index}.txt"), title);
    }
    std::fs::write(&input, text).expect("the patched dossier is written");

    let signed = sign(&fixture, &[]);
    assert_eq!(signed["ok"], Value::Bool(true));

    let report = json(&verify(&fixture, &[]));
    assert_check(&report, "reference_digest_ok", "passed");
    assert_check(&report, "signature_value_ok", "passed");
    assert!(
        !blocking(&report).contains(&"reference_digest_mismatch".to_owned()),
        "nothing may be rewritten under the signature: {:?}",
        checks(&report)
    );

    let listed = json(&binary_run(&[
        "list",
        &fixture.text("signed.es3"),
        "--json",
    ]));
    let listed: Vec<String> = listed["data"]["documents"]
        .as_array()
        .expect("an array of documents")
        .iter()
        .map(|document| {
            document["title"]
                .as_str()
                .expect("a title is a string")
                .to_owned()
        })
        .collect();
    assert_eq!(listed, titles);
}

// ---------------------------------------------------------------------------
// 9. A dossier never chooses what the operator's key signs
// ---------------------------------------------------------------------------

/// The default e-dossier namespace, as `create` writes it.
const ESZIGNO_NAMESPACE: &str = "https://www.microsec.hu/ds/e-szigno30#";

/// Rewrite the unsigned dossier in place, so a test can plant a value a
/// well-behaved `create` run would never write.
fn patch_input(fixture: &Fixture, replacements: &[(String, String)]) {
    let input = fixture.path("input.es3");
    let mut text = String::from_utf8(std::fs::read(&input).expect("the dossier is read"))
        .expect("it is UTF-8");
    for (from, to) in replacements {
        assert!(text.contains(from.as_str()), "the fixture holds {from}");
        text = text.replace(from.as_str(), to.as_str());
    }
    std::fs::write(&input, text).expect("the patched dossier is written");
}

/// A dossier that writes markup into the values a signature has to quote is
/// refused, one value at a time.
///
/// The digests are computed after the values are in the document, so a value
/// that reached the XML unescaped would let the dossier write the reference
/// set and the signed properties instead of describing them: an
/// attacker-chosen `ds:Reference` with no transforms, or a forged
/// `xades:CommitmentTypeIndication`, both under the operator's own key and
/// both of which `verify` would then accept.
#[test]
fn markup_in_a_dossier_never_reaches_the_signature_it_would_shape() {
    /// One planted value, and the extra flags the run needs to reach it.
    struct HostileCase {
        what: &'static str,
        replacements: Vec<(String, String)>,
        extra: Vec<String>,
    }

    // Each of these parses to a value holding `"`, `<`, `>` and `&`.
    const HOSTILE: &str = "a&quot;b&lt;c&gt;d&amp;e";
    let hostile_namespace = format!("urn:openszigno:test:{HOSTILE}");
    let pki = pki();
    let cases = vec![
        HostileCase {
            what: "the payload OBJREF and the object it names",
            replacements: vec![
                (
                    "OBJREF=\"obj0\"".to_owned(),
                    format!("OBJREF=\"{HOSTILE}\""),
                ),
                (
                    "<ds:Object Id=\"obj0\">".to_owned(),
                    format!("<ds:Object Id=\"{HOSTILE}\">"),
                ),
            ],
            extra: Vec::new(),
        },
        HostileCase {
            what: "the document profile Id",
            replacements: vec![("Id=\"profile0\"".to_owned(), format!("Id=\"{HOSTILE}\""))],
            extra: Vec::new(),
        },
        HostileCase {
            what: "the declared media type",
            replacements: vec![("type=\"text\"".to_owned(), format!("type=\"{HOSTILE}\""))],
            extra: Vec::new(),
        },
        HostileCase {
            what: "the declared subtype",
            replacements: vec![(
                "subtype=\"plain\"".to_owned(),
                format!("subtype=\"{HOSTILE}\""),
            )],
            extra: Vec::new(),
        },
        HostileCase {
            what: "the dossier namespace",
            replacements: vec![(
                format!("xmlns:es=\"{ESZIGNO_NAMESPACE}\""),
                format!("xmlns:es=\"{hostile_namespace}\""),
            )],
            extra: vec![
                "--allow-namespace".to_owned(),
                "urn:openszigno:test:a\"b<c>d&e".to_owned(),
            ],
        },
    ];
    for HostileCase {
        what,
        replacements,
        extra,
    } in cases
    {
        let fixture = fixture(&pki, 1);
        patch_input(&fixture, &replacements);
        let borrowed: Vec<&str> = extra.iter().map(String::as_str).collect();
        let output = sign_output(&fixture, &borrowed);
        let report = json(&output);
        assert_eq!(
            report["errors"][0]["code"], "document_not_signable",
            "{what}: {report}"
        );
        assert_eq!(output.status.code(), Some(4), "{what}");
        assert!(
            !fixture.path("signed.es3").exists(),
            "{what}: nothing may be written"
        );
    }
}

/// Unusual is not hostile. A dossier whose identifiers and media type are odd
/// but legal signs, and the signature has exactly the shape the format
/// mandates: four references, and one `xades:DataObjectFormat`.
#[test]
fn a_dossier_with_unusual_but_valid_values_signs_to_the_mandated_shape() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    patch_input(
        &fixture,
        &[
            (
                "OBJREF=\"obj0\"".to_owned(),
                "OBJREF=\"_\u{e9}rt.\u{e9}s-0\"".to_owned(),
            ),
            (
                "<ds:Object Id=\"obj0\">".to_owned(),
                "<ds:Object Id=\"_\u{e9}rt.\u{e9}s-0\">".to_owned(),
            ),
            (
                "Id=\"profile0\"".to_owned(),
                "Id=\"prof.\u{ed}l-0_x\"".to_owned(),
            ),
            (
                "subtype=\"plain\"".to_owned(),
                "subtype=\"x.unusual+test-1\"".to_owned(),
            ),
        ],
    );

    let signed = sign(&fixture, &[]);
    assert_eq!(signed["ok"], Value::Bool(true));
    let text = String::from_utf8(std::fs::read(fixture.path("signed.es3")).expect("it is read"))
        .expect("it is UTF-8");
    assert_eq!(text.matches("<ds:Reference ").count(), 4, "{text}");
    assert_eq!(text.matches("<xades:DataObjectFormat").count(), 1);
    assert!(text.contains("<xades:MimeType>text/x.unusual+test-1</xades:MimeType>"));
    assert!(text.contains("URI=\"#_\u{e9}rt.\u{e9}s-0\""));

    let report = json(&verify(&fixture, &[]));
    assert_check(&report, "reference_digest_ok", "passed");
    assert_check(&report, "signature_value_ok", "passed");
    assert_check(&report, "reference_scope_complete", "passed");
}

/// An existing signature whose reference resolves to the element the new
/// signature would go into, or to anything containing it, is a refusal.
///
/// Adding a `ds:Signature` changes the canonical form of its container and of
/// every ancestor of it, so such a reference stops matching. Only `URI=""`
/// and dossier-level cover used to be detected, which left an `es:Document`
/// with an `Id` of its own, referenced by `URI="#doc0"`, silently broken.
#[test]
fn a_signature_that_would_break_an_existing_reference_is_refused() {
    let pki = pki();
    let cases: [(&str, &str, Vec<&str>); 3] = [
        ("the es:Document it would be written into", "#doc0", vec![]),
        (
            "the es:Dossier it would be written into",
            "#root0",
            vec!["--scope", "dossier"],
        ),
        ("something this tool cannot resolve", "#nowhere", vec![]),
    ];
    for (what, uri, extra) in cases {
        let fixture = fixture(&pki, 1);
        patch_input(
            &fixture,
            &[
                (
                    "<es:Dossier ".to_owned(),
                    "<es:Dossier Id=\"root0\" ".to_owned(),
                ),
                (
                    "<es:Document>".to_owned(),
                    "<es:Document Id=\"doc0\">".to_owned(),
                ),
            ],
        );
        // One signature, written by this tool, then aimed at a target it
        // would never choose itself.
        assert_eq!(sign(&fixture, &[])["ok"], Value::Bool(true));
        let signed = String::from_utf8(
            std::fs::read(fixture.path("signed.es3")).expect("the signed dossier is read"),
        )
        .expect("it is UTF-8");
        assert!(signed.contains("URI=\"#obj0\""), "{what}");
        std::fs::write(
            fixture.path("input.es3"),
            signed.replace("URI=\"#obj0\"", &format!("URI=\"{uri}\"")),
        )
        .expect("the patched dossier is written");
        std::fs::remove_file(fixture.path("signed.es3")).expect("the output is removed");

        let output = sign_output(&fixture, &extra);
        let report = json(&output);
        assert_eq!(
            report["errors"][0]["code"], "document_already_signed",
            "{what}: {report}"
        );
        assert_eq!(output.status.code(), Some(4), "{what}");
        assert!(
            !fixture.path("signed.es3").exists(),
            "{what}: nothing may be written"
        );
    }
}

// ---------------------------------------------------------------------------
// 10. Co-signing
// ---------------------------------------------------------------------------

/// A document this tool has already signed can be signed again, by another
/// key, and both signatures verify.
///
/// Every identifier used to be derived from the document index alone, so the
/// second run collided with its own first signature and reported
/// `sign_failed`. The identifiers are disambiguated instead, and the first
/// signature is left exactly as it was.
#[test]
fn a_document_already_signed_by_this_tool_can_be_co_signed() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let first = issued_by(
        &CertSpec::signer("openSzigno Test Signer"),
        &rsa_key(keys::SIGNER_RSA2048),
        &root,
        &root_key,
    );
    let second = issued_by(
        &CertSpec::signer("openSzigno Second Signer"),
        &rsa_key(keys::SECOND_RSA2048),
        &root,
        &root_key,
    );
    let pki = Pki {
        root_der: root.der,
        signer_der: first.der,
        signer_key_der: pkcs8(keys::SIGNER_RSA2048),
        tsa_der: Vec::new(),
        tsa_key: rsa_key(keys::THIRD_RSA2048),
    };
    let fixture = fixture(&pki, 1);
    std::fs::write(fixture.path("second.key"), pkcs8(keys::SECOND_RSA2048))
        .expect("the second key is written");
    std::fs::write(fixture.path("second.crt"), &second.der)
        .expect("the second certificate is written");

    let signed = sign(&fixture, &[]);
    assert_eq!(signed["data"]["signatures"][0]["id"], "sig-doc0");
    let once = std::fs::read(fixture.path("signed.es3")).expect("the first output is read");
    std::fs::rename(fixture.path("signed.es3"), fixture.path("input.es3"))
        .expect("the signed dossier becomes the next run's input");

    let output = sign_with(&fixture, "second.key", "second.crt", &[]);
    let report = json(&output);
    assert!(
        output.status.success(),
        "the second run must succeed: {report}"
    );
    assert_eq!(report["data"]["signatures"][0]["id"], "sig-doc0-2");

    // The first signature is untouched: its bytes are still in the file.
    let twice = String::from_utf8(
        std::fs::read(fixture.path("signed.es3")).expect("the second output is read"),
    )
    .expect("it is UTF-8");
    let once = String::from_utf8(once).expect("it is UTF-8");
    let first_element = once
        .split_once("<ds:Signature ")
        .expect("the first signature is there")
        .1;
    let first_element = first_element
        .split_once("</ds:Signature>")
        .expect("it ends")
        .0;
    assert!(
        twice.contains(first_element),
        "the first signature must be left exactly as it was"
    );
    assert!(twice.contains("Id=\"signed-props-sig-doc0-2\""));

    let verified = json(&verify(&fixture, &[]));
    assert_eq!(
        verified["data"]["signatures"]
            .as_array()
            .expect("an array")
            .len(),
        2
    );
    assert_eq!(
        checks(&verified)
            .iter()
            .filter(|(code, status)| code == "signature_value_ok" && status == "passed")
            .count(),
        2,
        "both signatures verify: {:?}",
        checks(&verified)
    );
    let covered = verified["data"]["documents"][0]["covered_by"]
        .as_array()
        .expect("an array");
    let mut indices: Vec<i64> = covered
        .iter()
        .map(|entry| entry["signature_index"].as_i64().expect("an index"))
        .collect();
    indices.sort_unstable();
    assert_eq!(indices, vec![0, 1], "both signatures cover the document");
}
