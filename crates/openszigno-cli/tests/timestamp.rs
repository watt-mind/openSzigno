//! `timestamp`, end to end: what this tool writes is what this tool verifies.
//!
//! Every run here creates an unsigned dossier, timestamps it against a
//! loopback timestamp authority the test minted seconds earlier, and then
//! verifies the result against a trust store holding that authority's root.
//! The last step is the point of the suite: a container timestamp is only
//! worth writing if the verifier recomputes the same imprint over the same
//! elements, and nothing but running both sides proves that it does.
//!
//! A `verified` container timestamp here says the token checks out against the
//! anchor *this test chose to trust*. It is a statement about the shape of
//! what `timestamp` writes, never about anybody's identity.

mod online_support;

use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;

use online_support::common::{
    CertSpec, CrlSpec, TimestampSpec, build_crl, build_timestamp_token_for_imprint,
    extended_key_usage_extension, issued_by, keys, rsa_key, self_signed,
};
use online_support::{Reply, json, reserved, run, scratch, serve_on};
use rcgen::BasicConstraints;
use serde_json::Value;

/// The instant every run is judged at: inside the synthetic certificates'
/// validity and inside the synthetic CRL's freshness window.
const AT: &str = "2020-06-02T00:00:00Z";
/// The `genTime` the loopback timestamp authority stamps with.
const GEN_TIME: &str = "2020-06-02T00:00:10Z";
/// RFC 3161 `id-kp-timeStamping`.
const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";

// ---------------------------------------------------------------------------
// The synthetic PKI, on disk
// ---------------------------------------------------------------------------

/// A root and the timestamp authority it issued. No signing key appears
/// anywhere in this suite, because a container timestamp needs none.
struct Pki {
    root_der: Vec<u8>,
    tsa_der: Vec<u8>,
}

fn pki() -> Pki {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut tsa_spec = CertSpec::signer("openSzigno Test TSA");
    tsa_spec.custom_extensions = vec![extended_key_usage_extension(&[ID_KP_TIME_STAMPING], true)];
    let tsa = issued_by(&tsa_spec, &rsa_key(keys::THIRD_RSA2048), &root, &root_key);
    Pki {
        root_der: root.der,
        tsa_der: tsa.der,
    }
}

/// One test's working directory: an unsigned dossier and a trust store holding
/// the root.
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

/// Create an unsigned dossier with `documents` text documents.
fn create(fixture: &Fixture, documents: usize) {
    let mut arguments = vec![
        "create".to_owned(),
        "--output".to_owned(),
        fixture.text("input.es3"),
        "--title".to_owned(),
        "Synthetic timestamping fixture".to_owned(),
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
    let output = run(&borrowed);
    assert!(output.status.success(), "create failed: {output:?}");
}

fn fixture(pki: &Pki, documents: usize) -> Fixture {
    let fixture = Fixture {
        directory: scratch(),
    };
    std::fs::write(fixture.path("root.crt"), &pki.root_der).expect("the root is written");
    let anchors = fixture.path("store/anchors");
    std::fs::create_dir_all(&anchors).expect("the anchors directory is created");
    std::fs::write(anchors.join("root.der"), &pki.root_der).expect("the anchor is written");
    create(&fixture, documents);
    fixture
}

/// A revocation store holding one CRL from the root, which answers for the
/// timestamp authority's certificate.
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
    let answer = move |body: &[u8]| -> Vec<u8> {
        use der::{Decode as _, Encode as _};
        let request = TimeStampReq::from_der(body).expect("the CLI sent a TimeStampReq");
        let mut spec = TimestampSpec::new(rsa_key(keys::THIRD_RSA2048), tsa_der.clone(), GEN_TIME);
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

/// One `timestamp` run, with the input, the output and the mode spelled out.
/// `--json` is not implied: one test reads the human summary.
fn timestamp_output(fixture: &Fixture, input: &str, output: &str, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "timestamp".to_owned(),
        fixture.text(input),
        "--output".to_owned(),
        fixture.text(output),
    ];
    arguments.extend(extra.iter().map(|value| (*value).to_owned()));
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    run(&borrowed)
}

fn timestamp(fixture: &Fixture, url: &str, extra: &[&str]) -> Value {
    let mut arguments = vec!["--tsa", url, "--online-allow-private", "--json"];
    arguments.extend_from_slice(extra);
    json(&timestamp_output(
        fixture,
        "input.es3",
        "stamped.es3",
        &arguments,
    ))
}

fn verify(fixture: &Fixture, name: &str, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "verify".to_owned(),
        fixture.text(name),
        "--trust-store".to_owned(),
        fixture.text("store"),
        "--at".to_owned(),
        AT.to_owned(),
        "--json".to_owned(),
    ];
    arguments.extend(extra.iter().map(|value| (*value).to_owned()));
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    run(&borrowed)
}

/// Every check in a report, as `(code, status)` pairs.
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
fn a_dossier_timestamp_verifies_and_leaves_the_dossier_verdict_where_it_was() {
    let pki = pki();
    let fixture = fixture(&pki, 2);
    let (_authority, url) = timestamp_authority(&pki);
    let store = revocation_store(&fixture, &pki);

    // What the dossier's verdict is before anything is added to it.
    let before = json(&verify(
        &fixture,
        "input.es3",
        &["--revocation-store", &store],
    ));

    let report = timestamp(&fixture, &url, &["--tsa-cert", &fixture.text("root.crt")]);
    assert_eq!(report["ok"], Value::Bool(true));
    assert_eq!(report["command"], "timestamp");
    let timestamps = report["data"]["timestamps"].as_array().expect("an array");
    assert_eq!(timestamps.len(), 1);
    assert_eq!(timestamps[0]["scope"], "dossier");
    assert_eq!(timestamps[0]["document_index"], Value::Null);
    assert_eq!(timestamps[0]["id"], "ts-dossier");
    assert_eq!(timestamps[0]["gen_time"], GEN_TIME);
    assert!(report["data"]["bytes"].as_u64().is_some_and(|n| n > 0));
    assert_eq!(
        report["warnings"][0]["code"],
        "timestamped_dossier_unverified"
    );

    // The element itself: the placement, the includes in the order their
    // canonical octets are concatenated in, the canonicalization the verifier
    // is told to use, and one token.
    let written = std::fs::read_to_string(fixture.path("stamped.es3")).expect("readable");
    let element = element_of(&written);
    assert!(element.contains("Id=\"ts-dossier\""), "{element}");
    assert!(
        element.contains(
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
        ),
        "{element}"
    );
    let includes: Vec<&str> = element
        .match_indices("<xades:Include URI=\"#")
        .map(|(index, _)| &element[index..])
        .collect();
    assert_eq!(includes.len(), 2, "{element}");
    assert!(
        includes[0].starts_with("<xades:Include URI=\"#dossier\"/>"),
        "{element}"
    );
    assert!(
        includes[1].starts_with("<xades:Include URI=\"#documents\"/>"),
        "{element}"
    );
    assert_eq!(element.matches("<xades:EncapsulatedTimeStamp>").count(), 1);
    // `--tsa-cert` travels beside the token, outside everything the imprint
    // covers.
    assert!(element.contains("<xades:CertificateValues>"), "{element}");
    // The element is the last child of es:Dossier, which is what makes it a
    // dossier timestamp rather than an element at an undescribed placement.
    assert!(
        written.contains(&format!("{element}</es:Dossier>")),
        "{written}"
    );

    let output = verify(&fixture, "stamped.es3", &["--revocation-store", &store]);
    let after = json(&output);
    assert_check(&after, "dossier_timestamp_verified", "info");
    // The token is reported at the dossier level, with its own entry.
    let reported = after["data"]["timestamps"].as_array().expect("an array");
    assert_eq!(reported.len(), 1);
    assert_eq!(reported[0]["kind"], "dossier-timestamp");
    assert_eq!(reported[0]["verified"], Value::Bool(true));
    assert_eq!(reported[0]["gen_time"], GEN_TIME);
    // Carrying more evidence than the minimum never moves the verdict.
    assert_eq!(after["data"]["verdict"], before["data"]["verdict"]);
    assert_eq!(output.status.code(), before_status(&before));
}

/// The `es:TimeStamp` element out of a timestamped dossier, start tag to end
/// tag.
fn element_of(text: &str) -> String {
    let start = text.find("<es:TimeStamp").expect("the element is there");
    let end = text.find("</es:TimeStamp>").expect("the element ends") + "</es:TimeStamp>".len();
    text[start..end].to_owned()
}

/// The exit status a verdict maps to, taken from the untimestamped run so the
/// two are compared rather than restated.
fn before_status(before: &Value) -> Option<i32> {
    match before["data"]["verdict"].as_str() {
        Some("valid") => Some(0),
        _ => Some(7),
    }
}

#[test]
fn a_document_timestamp_covers_the_document_it_sits_in() {
    let pki = pki();
    let fixture = fixture(&pki, 2);
    let (_authority, url) = timestamp_authority(&pki);
    let store = revocation_store(&fixture, &pki);

    let report = timestamp(&fixture, &url, &["--scope", "document", "--document", "#1"]);
    let timestamps = report["data"]["timestamps"].as_array().expect("an array");
    assert_eq!(timestamps.len(), 1);
    assert_eq!(timestamps[0]["scope"], "document");
    assert_eq!(timestamps[0]["document_index"], 1);
    assert_eq!(timestamps[0]["id"], "ts-doc1");

    let after = json(&verify(
        &fixture,
        "stamped.es3",
        &["--revocation-store", &store],
    ));
    assert_check(&after, "document_timestamp_verified", "info");
    let reported = after["data"]["timestamps"].as_array().expect("an array");
    assert_eq!(reported[0]["kind"], "document-timestamp");
    assert_eq!(reported[0]["document_index"], 1);
}

/// Without `--document`, every document gets its own timestamp.
#[test]
fn document_scope_without_a_selector_timestamps_every_document() {
    let pki = pki();
    let fixture = fixture(&pki, 2);
    let (_authority, url) = timestamp_authority(&pki);
    let store = revocation_store(&fixture, &pki);

    let report = timestamp(&fixture, &url, &["--scope", "document"]);
    let timestamps = report["data"]["timestamps"].as_array().expect("an array");
    assert_eq!(timestamps.len(), 2);
    assert_eq!(timestamps[1]["id"], "ts-doc1");

    let after = json(&verify(
        &fixture,
        "stamped.es3",
        &["--revocation-store", &store],
    ));
    let verified = after["data"]["timestamps"]
        .as_array()
        .expect("an array")
        .iter()
        .filter(|entry| entry["verified"] == Value::Bool(true))
        .count();
    assert_eq!(verified, 2);
}

// ---------------------------------------------------------------------------
// 2. Evidence against the container
// ---------------------------------------------------------------------------

/// A dossier edited after it was timestamped is what the timestamp is for.
#[test]
fn a_tampered_dossier_makes_its_timestamp_invalid() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let (_authority, url) = timestamp_authority(&pki);
    let store = revocation_store(&fixture, &pki);
    timestamp(&fixture, &url, &[]);

    let path = fixture.path("stamped.es3");
    let text = std::fs::read_to_string(&path).expect("the output is readable");
    let tampered = text.replace(
        "Synthetic timestamping fixture",
        "Synthetic tampering fixture",
    );
    assert_ne!(tampered, text, "the title is there to be rewritten");
    std::fs::write(&path, tampered).expect("the tampered dossier is written");

    let output = verify(&fixture, "stamped.es3", &["--revocation-store", &store]);
    let report = json(&output);
    assert_check(&report, "dossier_timestamp_invalid", "failed");
    assert_eq!(report["data"]["verdict"], "invalid");
}

// ---------------------------------------------------------------------------
// 3. Refusals, none of which contact anything
// ---------------------------------------------------------------------------

#[test]
fn a_second_timestamp_at_the_same_placement_is_refused() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let (authority, url) = timestamp_authority(&pki);
    timestamp(&fixture, &url, &[]);
    let before = authority.seen().len();

    let output = timestamp_output(
        &fixture,
        "stamped.es3",
        "twice.es3",
        &["--tsa", &url, "--online-allow-private", "--json"],
    );
    let report = json(&output);
    assert_eq!(report["ok"], Value::Bool(false));
    assert_eq!(report["errors"][0]["code"], "timestamp_exists");
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        authority.seen().len(),
        before,
        "a refusal opens no socket at all"
    );
    assert!(
        !fixture.path("twice.es3").exists(),
        "nothing is written for a refused run"
    );
}

/// A dossier-level timestamp covers `es:Documents`, so adding anything inside
/// a document afterwards would break it. The refusal is the placement rule
/// `sign` applies, unchanged.
#[test]
fn a_document_timestamp_under_a_dossier_timestamp_is_refused() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let (_authority, url) = timestamp_authority(&pki);
    timestamp(&fixture, &url, &[]);

    let output = timestamp_output(
        &fixture,
        "stamped.es3",
        "inner.es3",
        &[
            "--tsa",
            &url,
            "--online-allow-private",
            "--json",
            "--scope",
            "document",
        ],
    );
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "document_already_signed");
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn a_selector_that_matches_nothing_is_refused_before_anything_is_contacted() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let (authority, url) = timestamp_authority(&pki);

    let output = timestamp_output(
        &fixture,
        "input.es3",
        "stamped.es3",
        &[
            "--tsa",
            &url,
            "--online-allow-private",
            "--json",
            "--scope",
            "document",
            "--document",
            "#9",
        ],
    );
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "document_not_found");
    assert_eq!(output.status.code(), Some(4));
    assert!(authority.seen().is_empty(), "nothing was asked of the TSA");
}

/// The destination policy is the one `verify --online` and `sign --tsa` obey:
/// a loopback authority is refused unless the caller says otherwise.
#[test]
fn a_refused_tsa_destination_is_a_tsa_failure() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let (_authority, url) = timestamp_authority(&pki);

    let output = timestamp_output(
        &fixture,
        "input.es3",
        "stamped.es3",
        &["--tsa", &url, "--json"],
    );
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "tsa_failed");
    assert_eq!(output.status.code(), Some(5));
    assert!(!fixture.path("stamped.es3").exists());
}

#[test]
fn an_existing_output_is_never_overwritten() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let (_authority, url) = timestamp_authority(&pki);
    std::fs::write(fixture.path("stamped.es3"), b"already here").expect("the file is written");

    let output = timestamp_output(
        &fixture,
        "input.es3",
        "stamped.es3",
        &["--tsa", &url, "--online-allow-private", "--json"],
    );
    assert_eq!(json(&output)["errors"][0]["code"], "output_exists");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        std::fs::read(fixture.path("stamped.es3")).expect("still readable"),
        b"already here"
    );
}

// ---------------------------------------------------------------------------
// 4. The human renderer
// ---------------------------------------------------------------------------

#[test]
fn the_human_summary_names_the_timestamp_and_the_boundary() {
    let pki = pki();
    let fixture = fixture(&pki, 1);
    let (_authority, url) = timestamp_authority(&pki);
    let output = timestamp_output(
        &fixture,
        "input.es3",
        "stamped.es3",
        &["--tsa", &url, "--online-allow-private"],
    );
    assert!(output.status.success(), "the run succeeded: {output:?}");
    let text = String::from_utf8(output.stdout).expect("the summary is UTF-8");
    assert!(text.contains("Timestamped"), "{text}");
    assert!(text.contains("ts-dossier | scope=dossier"), "{text}");
    assert!(text.contains(&format!("genTime={GEN_TIME}")), "{text}");
    assert!(text.contains("Timestamping verified nothing."), "{text}");
}

