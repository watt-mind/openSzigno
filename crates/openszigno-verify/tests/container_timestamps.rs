//! Stage G: the container `es:TimeStamp`, at dossier and document level.
//!
//! An `es:TimeStamp` protects the elements its `xades:Include` children name,
//! so these tests are about three things a signature timestamp never has to
//! answer: which elements were resolved, whether they are the ones the
//! container mandates, and in what order their canonical forms were
//! concatenated. Every token is generated at test time by a synthetic
//! timestamp authority; nothing here comes from a real dossier.

mod common;

use common::{
    C14N_EXC, CertSpec, ContainerTimestampSpec, DossierSpec, TestKey, TimestampPlacement,
    TimestampSpec, build, document_signature, extended_key_usage_extension, issued_by, keys,
    rsa_key, self_signed,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{
    FixedClock, MemoryTrustStore, NoRevocation, NoTrust, RoxmltreeC14n, TimestampKind, Verdict,
    VerifyOptions, VerifyReport, parse_rfc3339, verify,
};
use rcgen::BasicConstraints;

const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";

struct Pki {
    root_der: Vec<u8>,
    signer_der: Vec<u8>,
    signer_key: TestKey,
    tsa_der: Vec<u8>,
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
        signer_key,
        tsa_der: tsa.der,
    }
}

fn token(pki: &Pki) -> TimestampSpec {
    TimestampSpec::new(
        rsa_key(keys::THIRD_RSA2048),
        pki.tsa_der.clone(),
        "2020-06-01T09:00:00Z",
    )
}

/// A dossier with one signed document and the given container timestamps.
fn dossier(pki: &Pki, timestamps: Vec<ContainerTimestampSpec>) -> String {
    let spec = DossierSpec {
        document_signature: Some(document_signature(vec![pki.signer_der.clone()])),
        container_timestamps: timestamps,
        ..Default::default()
    };
    build(&spec, &[("doc", &pki.signer_key)])
}

fn run(xml: &str, anchors: Vec<Vec<u8>>) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339("2020-06-02T00:00:00Z").expect("the time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some("2020-06-02T00:00:00Z".to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

/// The same run with no trust anchors at all, which is a gap in the caller's
/// material rather than a finding about the dossier.
fn run_without_anchors(xml: &str) -> VerifyReport {
    let trust = NoTrust;
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339("2020-06-02T00:00:00Z").expect("the time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some("2020-06-02T00:00:00Z".to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

fn dossier_check(report: &VerifyReport, code: CheckCode) -> &openszigno_verify::Check {
    report
        .checks
        .iter()
        .find(|check| check.code == code)
        .unwrap_or_else(|| {
            panic!(
                "expected {} among {:?}",
                code.as_str(),
                report
                    .checks
                    .iter()
                    .map(|check| format!("{}={}", check.code.as_str(), check.status.as_str()))
                    .collect::<Vec<_>>()
            )
        })
}

fn assert_dossier_check(report: &VerifyReport, code: CheckCode, status: CheckStatus) {
    assert_eq!(dossier_check(report, code).status, status);
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn a_dossier_timestamp_over_the_mandated_elements_verifies() {
    let pki = pki();
    let xml = dossier(&pki, vec![ContainerTimestampSpec::dossier(token(&pki))]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_dossier_check(
        &report,
        CheckCode::DossierTimestampVerified,
        CheckStatus::Info,
    );
    assert_eq!(report.counts.timestamps, 1);
    assert_eq!(report.counts.timestamps_verified, 1);
    assert_eq!(report.timestamps.len(), 1);
    assert_eq!(report.timestamps[0].kind, TimestampKind::DossierTimestamp);
    assert_eq!(report.timestamps[0].document_index, None);
    assert!(report.timestamps[0].verified);
    assert_eq!(
        report.timestamps[0].gen_time.as_deref(),
        Some("2020-06-01T09:00:00Z")
    );
    assert!(report.timestamps[0].tsa_certificate.is_some());
}

#[test]
fn a_document_timestamp_over_the_mandated_elements_verifies() {
    let pki = pki();
    let xml = dossier(&pki, vec![ContainerTimestampSpec::document(token(&pki))]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_dossier_check(
        &report,
        CheckCode::DocumentTimestampVerified,
        CheckStatus::Info,
    );
    assert_eq!(report.timestamps[0].kind, TimestampKind::DocumentTimestamp);
    assert_eq!(report.timestamps[0].document_index, Some(0));
    assert_eq!(report.counts.timestamps_verified, 1);
}

#[test]
fn a_verified_container_timestamp_does_not_change_a_signature_verdict() {
    let pki = pki();
    let with = dossier(&pki, vec![ContainerTimestampSpec::dossier(token(&pki))]);
    let without = dossier(&pki, Vec::new());
    let with = run(&with, vec![pki.root_der.clone()]);
    let without = run(&without, vec![pki.root_der.clone()]);

    // The signature is indeterminate either way — it has no signature
    // timestamp and no revocation data — and carrying a container timestamp
    // neither helps nor hurts it.
    assert_eq!(with.signatures[0].verdict, without.signatures[0].verdict);
    let names = |report: &VerifyReport| {
        report.signatures[0]
            .checks
            .iter()
            .map(|check| format!("{}={}", check.code.as_str(), check.status.as_str()))
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&with), names(&without));
}

#[test]
fn an_exclusive_canonicalization_method_is_honoured() {
    let pki = pki();
    let mut timestamp = ContainerTimestampSpec::dossier(token(&pki));
    timestamp.c14n = Some(C14N_EXC.to_owned());
    let xml = dossier(&pki, vec![timestamp]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_dossier_check(
        &report,
        CheckCode::DossierTimestampVerified,
        CheckStatus::Info,
    );
}

// ---------------------------------------------------------------------------
// Evidence against the container
// ---------------------------------------------------------------------------

#[test]
fn an_imprint_that_does_not_match_makes_the_dossier_invalid() {
    let pki = pki();
    let mut timestamp = ContainerTimestampSpec::dossier(token(&pki));
    timestamp.wrong_imprint = true;
    let xml = dossier(&pki, vec![timestamp]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_dossier_check(
        &report,
        CheckCode::DossierTimestampInvalid,
        CheckStatus::Failed,
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    // The container's failure is the container's: the signature keeps the
    // verdict its own evidence earned.
    assert_eq!(report.signatures[0].verdict, Verdict::Indeterminate);
    assert_eq!(report.counts.timestamps_verified, 0);
}

#[test]
fn the_order_of_the_includes_is_part_of_what_is_digested() {
    let pki = pki();
    // The token is built over the canonical forms in the order the `Include`
    // elements are emitted. Reversing them after the fact must not still match:
    // if it did, an attacker could reorder what a timestamp protects.
    let mut timestamp = ContainerTimestampSpec::dossier(token(&pki));
    timestamp.includes = vec!["#documents".to_owned(), "#dossier-profile".to_owned()];
    let ordered = dossier(&pki, vec![timestamp]);
    let reordered = ordered
        .replace(
            "<xades:Include URI=\"#documents\" referencedData=\"true\"/><xades:Include URI=\"#dossier-profile\" referencedData=\"true\"/>",
            "<xades:Include URI=\"#dossier-profile\" referencedData=\"true\"/><xades:Include URI=\"#documents\" referencedData=\"true\"/>",
        );
    assert_ne!(ordered, reordered, "the fixture was rewritten");
    let report = run(&reordered, vec![pki.root_der.clone()]);

    assert_dossier_check(
        &report,
        CheckCode::DossierTimestampInvalid,
        CheckStatus::Failed,
    );
}

#[test]
fn a_token_that_is_not_a_token_is_reported_as_invalid() {
    let pki = pki();
    let mut spec = token(&pki);
    spec.raw_token = Some(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
    let xml = dossier(&pki, vec![ContainerTimestampSpec::dossier(spec)]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_dossier_check(
        &report,
        CheckCode::DossierTimestampInvalid,
        CheckStatus::Failed,
    );
}

// ---------------------------------------------------------------------------
// Gaps, which are missing information rather than findings
// ---------------------------------------------------------------------------

#[test]
fn a_timestamp_that_does_not_cover_the_mandated_elements_is_not_checked() {
    let pki = pki();
    let mut timestamp = ContainerTimestampSpec::dossier(token(&pki));
    timestamp.includes = vec!["#documents".to_owned()];
    let xml = dossier(&pki, vec![timestamp]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    let check = dossier_check(&report, CheckCode::DossierTimestampNotChecked);
    assert_eq!(check.status, CheckStatus::Info);
    assert!(
        check.message.contains("DossierProfile"),
        "the message names what was not covered: {}",
        check.message
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

#[test]
fn a_document_timestamp_must_cover_the_payload_object() {
    let pki = pki();
    let mut timestamp = ContainerTimestampSpec::document(token(&pki));
    timestamp.includes = vec!["#prof0".to_owned()];
    let xml = dossier(&pki, vec![timestamp]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    let check = dossier_check(&report, CheckCode::DocumentTimestampNotChecked);
    assert_eq!(check.status, CheckStatus::Info);
    assert!(check.message.contains("payload"), "{}", check.message);
}

#[test]
fn an_include_that_resolves_to_nothing_is_not_digested() {
    let pki = pki();
    let mut timestamp = ContainerTimestampSpec::dossier(token(&pki));
    timestamp.includes = vec![
        "#dossier-profile".to_owned(),
        "#documents".to_owned(),
        "#nothing-here".to_owned(),
    ];
    let xml = dossier(&pki, vec![timestamp]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    let check = dossier_check(&report, CheckCode::DossierTimestampNotChecked);
    assert_eq!(check.status, CheckStatus::Info);
    assert!(
        check.message.contains("resolves to nothing"),
        "{}",
        check.message
    );
}

#[test]
fn an_external_include_is_never_dereferenced() {
    let pki = pki();
    let mut timestamp = ContainerTimestampSpec::dossier(token(&pki));
    timestamp.includes = vec!["http://example.invalid/thing".to_owned()];
    let xml = dossier(&pki, vec![timestamp]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    let check = dossier_check(&report, CheckCode::DossierTimestampNotChecked);
    assert_eq!(check.status, CheckStatus::Info);
    assert!(check.message.contains("same-document"), "{}", check.message);
}

#[test]
fn a_selection_form_this_build_does_not_implement_is_not_guessed_at() {
    let pki = pki();
    let mut timestamp = ContainerTimestampSpec::dossier(token(&pki));
    timestamp.reference_info = true;
    let xml = dossier(&pki, vec![timestamp]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_dossier_check(
        &report,
        CheckCode::DossierTimestampNotChecked,
        CheckStatus::Info,
    );
}

#[test]
fn a_timestamp_with_no_includes_has_no_implicit_selection() {
    let pki = pki();
    let mut timestamp = ContainerTimestampSpec::dossier(token(&pki));
    timestamp.includes = Vec::new();
    let xml = dossier(&pki, vec![timestamp]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    let check = dossier_check(&report, CheckCode::DossierTimestampNotChecked);
    assert!(
        check.message.contains("implicit data selection"),
        "{}",
        check.message
    );
}

#[test]
fn an_undecodable_token_is_not_checked_rather_than_condemned() {
    let pki = pki();
    let mut timestamp = ContainerTimestampSpec::dossier(token(&pki));
    timestamp.token = None;
    let xml = dossier(&pki, vec![timestamp]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_dossier_check(
        &report,
        CheckCode::DossierTimestampNotChecked,
        CheckStatus::Info,
    );
}

#[test]
fn a_timestamp_at_an_undescribed_placement_is_not_checked() {
    let pki = pki();
    let mut timestamp = ContainerTimestampSpec::dossier(token(&pki));
    timestamp.placement = TimestampPlacement::Stray;
    let xml = dossier(&pki, vec![timestamp]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    let check = dossier_check(&report, CheckCode::DossierTimestampNotChecked);
    assert!(
        check.message.contains("does not describe"),
        "{}",
        check.message
    );
}

#[test]
fn a_missing_trust_store_is_a_gap_not_a_finding() {
    let pki = pki();
    let xml = dossier(&pki, vec![ContainerTimestampSpec::dossier(token(&pki))]);
    let report = run_without_anchors(&xml);

    // No anchors means the TSA path cannot be judged. That is a gap in the
    // caller's material, so the dossier must not be reported `invalid` for
    // carrying evidence the caller cannot check.
    assert_dossier_check(
        &report,
        CheckCode::DossierTimestampNotChecked,
        CheckStatus::Info,
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.counts.timestamps_verified, 0);
}

#[test]
fn several_container_timestamps_are_each_reported() {
    let pki = pki();
    let xml = dossier(
        &pki,
        vec![
            ContainerTimestampSpec::dossier(token(&pki)),
            ContainerTimestampSpec::document(token(&pki)),
        ],
    );
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_eq!(report.timestamps.len(), 2);
    assert_eq!(report.counts.timestamps_verified, 2);
    assert_dossier_check(
        &report,
        CheckCode::DossierTimestampVerified,
        CheckStatus::Info,
    );
    assert_dossier_check(
        &report,
        CheckCode::DocumentTimestampVerified,
        CheckStatus::Info,
    );
}
