//! CLI-level tests for `openszigno verify`: the envelope, the exit statuses,
//! and the rule that no release so far reports a signature as valid.
//!
//! Cryptographically correct signatures are covered by the verify crate's own
//! suite, which owns the in-tests signer. What matters here is the process
//! contract: one JSON object on stdout, stable codes, and the right status.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

fn scratch() -> TempDir {
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory must resolve");
    tempfile::tempdir_in(base).expect("a temporary directory must be available")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(args)
        .output()
        .expect("CLI must run")
}

fn parse_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout must be exactly one JSON value")
}

fn status(output: &Output) -> i32 {
    output.status.code().expect("the process exited normally")
}

/// A synthetic self-signed root, generated once by the verify crate's test
/// helper and committed so the trust-store loader can be exercised from the
/// CLI. It signs nothing and must never be trusted anywhere.
const SYNTHETIC_ROOT_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIDmTCCAoGgAwIBAgIUZG45lskFVacMHiONOuIPSegLnq8wDQYJKoZIhvcNAQEL\n\
BQAwVDEdMBsGA1UEAwwUb3BlblN6aWdubyBUZXN0IFJvb3QxJjAkBgNVBAoMHW9w\n\
ZW5Temlnbm8gc3ludGhldGljIHRlc3QgUEtJMQswCQYDVQQGDAJIVTAeFw0xOTAx\n\
MDEwMDAwMDBaFw0zOTAxMDEwMDAwMDBaMFQxHTAbBgNVBAMMFG9wZW5Temlnbm8g\n\
VGVzdCBSb290MSYwJAYDVQQKDB1vcGVuU3ppZ25vIHN5bnRoZXRpYyB0ZXN0IFBL\n\
STELMAkGA1UEBgwCSFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCn\n\
xR+30I7xutDvJbHkR18AYq7hjFuXdGHLQuAAq3sZr1G63h0ZpBFRVE31xpagmlTF\n\
Nk1XMRoRuNLMG/IJ5bdoKQDL/4tkKr7MAALpG9WDw235gDrK4gYCgbA8W3MwAjuh\n\
sKkr6mEZCc+KOWhsUyeCVL0NNhdlGyzchq2N5fbhE4a4qrftkFxNJ8lCDFB7IcQt\n\
A1m19XS0Vc3C7ZyCOAXoJQXbb6HONOLCTWlcthwi5gm4Fn34H1LgqXcgH+Nsc88a\n\
CrrUakqbo+JltMVXFAaNXtwHd2rJnetzqhMiRxl8lryMNfqmOez8/wjr+b2YqjG7\n\
Wer1Wu9Cq0Aa3gFb2ohZAgMBAAGjYzBhMB8GA1UdIwQYMBaAFE6r2sfFIsRjOxJ6\n\
giFoZIobZHzbMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUTqvax8UixGM7EnqC\n\
IWhkihtkfNswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAEoTO\n\
ub3ByQoDGA415Ly7Lyy5UYnggmjd1JxpuAtXp51xKQ8oVi+cDPi7BK4aA/wj/LK8\n\
GR3VHe3HdxqhoLe69F6UNsJPufD19po6EnNK0gSeqwUXGqbYgriEkHc/nLLlqzvx\n\
9tJ8kau/rOKL2Nnewzv59wf8THUyMnJGOl+kUvGpuXes0Fqnqz1cYebRC8zYIrf2\n\
fRQ8DehwTa0frmItj1DVchdPQdWzy+Cznjxom2sfGrEAeZD0KTtRPGYCF6hzSrvv\n\
+vmFOYu2UQ68U+n86xV+QLI6HgvmJp3bWSCNPpPSu1p06Gdrcvk2R2687w5dLGE3\n\
5gI0rRIvJsSqUD4gDw==\n\
-----END CERTIFICATE-----\n\
";

/// A trust store in the documented layout.
fn trust_store(directory: &Path) -> PathBuf {
    let store = directory.join("store");
    std::fs::create_dir_all(store.join("anchors")).expect("the anchors directory is created");
    std::fs::create_dir_all(store.join("intermediates"))
        .expect("the intermediates directory is created");
    std::fs::write(store.join("anchors/root.pem"), SYNTHETIC_ROOT_PEM)
        .expect("the anchor is written");
    store
}

#[test]
fn a_configured_trust_store_is_reported_as_configured() {
    let directory = scratch();
    let store = trust_store(directory.path());
    // A subdirectory inside the store is skipped rather than followed.
    std::fs::create_dir(store.join("anchors/nested")).expect("a subdirectory is created");
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--trust-store",
        store.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(status(&output), 7);
    let response = parse_json(&output);
    assert_eq!(response["data"]["policy"]["trust_store"], "configured");
    assert!(response["data"]["policy"]["trust_snapshot"].is_null());
}

/// A directory holding certificates directly, with no  subdirectory,
/// is read as a bag of anchors.
#[test]
fn a_flat_trust_store_directory_works() {
    let directory = scratch();
    let store = directory.path().join("flat");
    std::fs::create_dir(&store).expect("the store directory is created");
    std::fs::write(store.join("root.pem"), SYNTHETIC_ROOT_PEM).expect("the anchor is written");
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--trust-store",
        store.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(status(&output), 7);
    assert_eq!(
        parse_json(&output)["data"]["policy"]["trust_store"],
        "configured"
    );
}

#[test]
fn a_trust_store_that_is_not_a_directory_fails() {
    let directory = scratch();
    let path = directory.path().join("not-a-directory");
    std::fs::write(&path, SYNTHETIC_ROOT_PEM).expect("the file is written");
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--trust-store",
        path.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(status(&output), 3);
    assert_eq!(
        parse_json(&output)["errors"][0]["code"],
        "trust_store_invalid"
    );
}

#[test]
fn a_missing_trust_store_directory_fails() {
    let directory = scratch();
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--trust-store",
        directory.path().join("absent").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(status(&output), 3);
}

/// A dossier carrying a syntactically valid signature whose digests are wrong.
/// Nothing here is signed: the point is that the tool says so.
fn unverifiable_dossier() -> String {
    r##"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><es:DossierProfile Id="dossier-profile" OBJREF="documents"><es:Title>Synthetic unverifiable dossier</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate></es:DossierProfile><es:Documents Id="documents"><es:Document><es:DocumentProfile Id="prof0" OBJREF="obj0"><es:Title>synthetic</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="text" subtype="plain"/></es:Format><es:SourceSize sizeValue="5" sizeUnit="B"/><es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform></es:DocumentProfile><ds:Object Id="obj0">aGVsbG8=</ds:Object><ds:Signature Id="sig0"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#obj0"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference><ds:Reference URI="#prof0"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference><ds:Reference URI="#sigobj0"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue><ds:Object Id="sigobj0"><es:SignatureProfile Id="sigprof0"><es:SignerName>Synthetic Signer</es:SignerName><es:Type>signature</es:Type><es:Generator>openSzigno tests</es:Generator></es:SignatureProfile></ds:Object></ds:Signature></es:Document></es:Documents></es:Dossier>"##
        .to_owned()
}

#[test]
fn an_unsigned_dossier_is_indeterminate_and_exits_seven() {
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(status(&output), 7);
    let response = parse_json(&output);
    assert_eq!(response["schema_version"], 1);
    assert_eq!(response["ok"], true);
    assert_eq!(response["command"], "verify");
    assert_eq!(response["input"]["format"], "microsec-es3");
    assert_eq!(response["data"]["verdict"], "indeterminate");
    assert_eq!(response["data"]["counts"]["signatures"], 0);
    let codes: Vec<&str> = response["data"]["checks"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|check| check["code"].as_str().expect("a string"))
        .collect();
    assert!(codes.contains(&"no_signatures"));
    assert_eq!(response["errors"], Value::Array(Vec::new()));
}

#[test]
fn a_signature_that_does_not_verify_exits_six() {
    let directory = scratch();
    let path = directory.path().join("unverifiable.es3");
    std::fs::write(&path, unverifiable_dossier()).expect("the fixture is written");
    let output = run(&["verify", path.to_str().unwrap(), "--json"]);
    assert_eq!(status(&output), 6);
    let response = parse_json(&output);
    assert_eq!(response["data"]["verdict"], "invalid");
    assert_eq!(response["data"]["counts"]["signatures_invalid"], 1);
    let codes: Vec<&str> = response["data"]["signatures"][0]["checks"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|check| check["code"].as_str().expect("a string"))
        .collect();
    assert!(codes.contains(&"reference_digest_mismatch"));
    // No trust anchors, so no path, so nothing to ask a CRL about: the tool
    // says it does not know rather than skipping the stage silently.
    assert!(codes.contains(&"revocation_status_unknown"));
    // The signature carries no timestamp, which is reported rather than
    // assumed away.
    assert!(codes.contains(&"signature_timestamp_absent"));
}

/// The signature object carries the phase-2 fields, so a consumer can read the
/// XAdES view, the timestamps, and the validation time without re-deriving
/// them from the check list.
#[test]
fn the_signature_object_carries_the_phase_two_fields() {
    let directory = scratch();
    let path = directory.path().join("unverifiable.es3");
    std::fs::write(&path, unverifiable_dossier()).expect("the fixture is written");
    let output = run(&[
        "verify",
        path.to_str().unwrap(),
        "--json",
        "--at",
        "2020-06-01T00:00:00Z",
    ]);
    let response = parse_json(&output);
    let signature = &response["data"]["signatures"][0];
    assert_eq!(signature["validation_time"], "2020-06-01T00:00:00Z");
    assert_eq!(signature["validation_time_source"], "at_flag");
    assert_eq!(signature["timestamps"], Value::Array(Vec::new()));
    // This fixture carries no XAdES at all, which the report states rather
    // than omitting.
    assert_eq!(signature["xades"]["present"], false);
    assert_eq!(signature["xades"]["signing_certificate"], Value::Null);
    assert_eq!(signature["xades"]["signature_timestamps"], 0);
    assert_eq!(
        signature["xades"]["unvalidated_properties"],
        Value::Array(Vec::new())
    );
}

/// The per-document coverage inventory is part of the JSON contract: every
/// modelled document, in source order, with what covers it. Nothing here
/// signs anything, so every document is `uncovered` and the run is capped at
/// `indeterminate`.
#[test]
fn the_document_coverage_inventory_is_reported() {
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(status(&output), 7);
    let response = parse_json(&output);
    let documents = response["data"]["documents"]
        .as_array()
        .expect("the document inventory is an array");
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0]["index"], 0);
    assert_eq!(documents[0]["coverage"], "uncovered");
    assert_eq!(documents[0]["nested_dossier"], false);
    assert_eq!(documents[0]["covered_by"], Value::Array(Vec::new()));
    assert!(documents[0]["object_ref"].is_string());
    // A title never appears in the report.
    assert!(documents[0]["title"].is_null());
    assert_eq!(response["data"]["counts"]["documents_covered"], 0);
    assert_eq!(response["data"]["counts"]["documents_uncovered"], 1);
    assert_eq!(response["data"]["counts"]["documents_undetermined"], 0);
    let codes: Vec<&str> = response["data"]["checks"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|check| check["code"].as_str().expect("a string"))
        .collect();
    assert!(codes.contains(&"documents_uncovered"));
}

/// A document covered only by a signature that does not verify is
/// `covered_unverified`: coverage and cryptographic outcome are separate
/// answers, and the report keeps them apart.
#[test]
fn a_document_covered_by_a_failing_signature_is_covered_unverified() {
    let directory = scratch();
    let path = directory.path().join("unverifiable.es3");
    std::fs::write(&path, unverifiable_dossier()).expect("the fixture is written");
    let output = run(&["verify", path.to_str().unwrap(), "--json"]);
    let response = parse_json(&output);
    let document = &response["data"]["documents"][0];
    assert_eq!(document["coverage"], "covered_unverified");
    assert_eq!(document["covered_by"][0]["signature_index"], 0);
    assert_eq!(document["covered_by"][0]["via"], "direct");
    assert_eq!(document["covered_by"][0]["verdict"], "invalid");
}

/// Human output carries one coverage line per document.
#[test]
fn human_output_reports_document_coverage() {
    let output = run(&["verify", fixture("plain-base64.es3").to_str().unwrap()]);
    let text = String::from_utf8(output.stdout).expect("UTF-8");
    assert!(text.contains("document 0: uncovered"), "got: {text}");
}

/// Human output must state the verdict it reached and the revocation policy it
/// reached it under, and must not call an invalid signature valid.
#[test]
fn human_output_never_claims_validity() {
    let directory = scratch();
    let path = directory.path().join("unverifiable.es3");
    std::fs::write(&path, unverifiable_dossier()).expect("the fixture is written");
    let output = run(&["verify", path.to_str().unwrap()]);
    let text = String::from_utf8(output.stdout).expect("UTF-8");
    assert!(text.contains("Verification verdict: invalid"));
    assert!(text.contains("Revocation policy: offline"));
    assert!(text.contains("validation time:"));
    assert!(!text.contains("verdict: valid"));
}

/// A structural failure during `verify` still exits 4, so a caller can tell
/// "this is not a dossier" apart from "these signatures do not verify".
#[test]
fn a_structural_failure_still_exits_four() {
    let output = run(&["verify", fixture("doctype.es3").to_str().unwrap(), "--json"]);
    assert_eq!(status(&output), 4);
    let response = parse_json(&output);
    assert_eq!(response["ok"], false);
    assert_eq!(response["errors"][0]["code"], "unsafe_xml");
    assert_eq!(response["data"], Value::Null);
}

#[test]
fn an_unusable_trust_store_fails_the_run() {
    let directory = scratch();
    let store = directory.path().join("store");
    std::fs::create_dir(&store).expect("the store directory is created");
    std::fs::write(store.join("junk.pem"), b"not a certificate").expect("the file is written");
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--trust-store",
        store.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(status(&output), 3);
    let response = parse_json(&output);
    assert_eq!(response["errors"][0]["code"], "trust_store_invalid");
    let message = response["errors"][0]["message"]
        .as_str()
        .expect("a message");
    assert!(
        !message.contains("junk.pem"),
        "the message must not name a file"
    );
}

#[test]
fn an_empty_trust_store_fails_rather_than_trusting_nothing_silently() {
    let directory = scratch();
    let store = directory.path().join("store");
    std::fs::create_dir(&store).expect("the store directory is created");
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--trust-store",
        store.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(status(&output), 3);
    assert_eq!(
        parse_json(&output)["errors"][0]["code"],
        "trust_store_invalid"
    );
}

#[test]
fn a_malformed_validation_time_is_a_usage_error() {
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--at",
        "yesterday",
        "--json",
    ]);
    assert_eq!(status(&output), 2);
    assert_eq!(parse_json(&output)["errors"][0]["code"], "usage_error");
}

#[test]
fn the_validation_time_is_reported_as_requested() {
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--at",
        "2020-06-01T00:00:00Z",
        "--json",
    ]);
    let response = parse_json(&output);
    assert_eq!(
        response["data"]["verification_time"]["requested"],
        "2020-06-01T00:00:00Z"
    );
    assert_eq!(
        response["data"]["verification_time"]["effective"],
        "2020-06-01T00:00:00Z"
    );
    assert_eq!(response["data"]["verification_time"]["source"], "requested");
}

/// `verify` reports what it did rather than the "not performed" capability
/// warning, which keeps its meaning for the four reading commands.
#[test]
fn verify_does_not_emit_the_not_performed_warning() {
    let directory = scratch();
    let path = directory.path().join("unverifiable.es3");
    std::fs::write(&path, unverifiable_dossier()).expect("the fixture is written");
    let output = run(&["verify", path.to_str().unwrap(), "--json"]);
    let response = parse_json(&output);
    let codes: Vec<&str> = response["warnings"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|warning| warning["code"].as_str().expect("a string"))
        .collect();
    assert!(!codes.contains(&"cryptographic_verification_not_performed"));

    let inspect = run(&["inspect", path.to_str().unwrap(), "--json"]);
    let inspect = parse_json(&inspect);
    let codes: Vec<&str> = inspect["warnings"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|warning| warning["code"].as_str().expect("a string"))
        .collect();
    assert!(codes.contains(&"cryptographic_verification_not_performed"));
}

/// `--allow-legacy-algorithms` is reported in the policy and announced in the
/// human output, so a reader always knows the run was not held to the default
/// policy.
#[test]
fn the_legacy_flag_is_reported_in_the_policy() {
    let path = fixture("plain-base64.es3");
    let path = path.to_str().unwrap();

    let strict = parse_json(&run(&["verify", path, "--json"]));
    assert_eq!(
        strict["data"]["policy"]["legacy_algorithms_allowed"],
        Value::Bool(false)
    );

    let lenient = parse_json(&run(&[
        "verify",
        path,
        "--allow-legacy-algorithms",
        "--json",
    ]));
    assert_eq!(
        lenient["data"]["policy"]["legacy_algorithms_allowed"],
        Value::Bool(true)
    );
    let digests: Vec<&str> = lenient["data"]["policy"]["digest_algorithms"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|value| value.as_str().expect("a string"))
        .collect();
    assert!(digests.contains(&"sha1"));

    let output = run(&["verify", path, "--allow-legacy-algorithms"]);
    let text = String::from_utf8(output.stdout).expect("UTF-8");
    assert!(text.contains("Legacy algorithms were admitted for diagnosis"));
}

/// The trust store is all-or-nothing: one malformed entry alongside a good one
/// fails the whole store, because a half-loaded store silently changes what
/// "trusted" means.
#[test]
fn one_malformed_entry_fails_the_whole_trust_store() {
    let directory = scratch();
    let store = directory.path().join("store");
    std::fs::create_dir_all(store.join("anchors")).expect("the anchors directory is created");
    std::fs::write(store.join("anchors/good.pem"), SYNTHETIC_ROOT_PEM)
        .expect("the anchor is written");
    // A syntactically valid PEM block whose contents are not a certificate.
    std::fs::write(
        store.join("anchors/bad.pem"),
        "-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n",
    )
    .expect("the bad entry is written");

    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--trust-store",
        store.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(status(&output), 3);
    let response = parse_json(&output);
    assert_eq!(response["errors"][0]["code"], "trust_store_invalid");
    let message = response["errors"][0]["message"]
        .as_str()
        .expect("a message");
    assert!(
        !message.contains("bad.pem"),
        "the message must not name a file"
    );
    assert!(
        message.contains("block 1"),
        "the message names the entry: {message}"
    );
}

/// Two concatenated PEM blocks in one file are both loaded, and a store whose
/// second block is malformed fails.
#[test]
fn a_pem_bundle_is_validated_block_by_block() {
    let directory = scratch();
    let store = directory.path().join("store");
    std::fs::create_dir_all(&store).expect("the store directory is created");
    let bundle = format!(
        "{SYNTHETIC_ROOT_PEM}-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n"
    );
    std::fs::write(store.join("bundle.pem"), bundle).expect("the bundle is written");
    let output = run(&[
        "verify",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--trust-store",
        store.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(status(&output), 3);
    let message = parse_json(&output)["errors"][0]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(message.contains("block 2"), "{message}");
}
