//! Stage F: RFC 3161 signature timestamps, and the validation time they move.
//!
//! Every token here is generated at test time by a synthetic timestamp
//! authority. Nothing is derived from a real dossier or a real TSA.

mod common;

use common::{
    CertSpec, DossierSpec, SigSpec, TestKey, TimestampSpec, build, document_signature,
    extended_key_usage_extension, issued_by, keys, rsa_key, self_signed,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::report::ValidationTimeSource;
use openszigno_verify::{
    FixedClock, MemoryTrustStore, NoRevocation, NoTrust, RoxmltreeC14n, SystemClock, Verdict,
    VerifyOptions, VerifyReport, parse_rfc3339, verify,
};
use rcgen::BasicConstraints;

const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const ID_KP_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";

/// Verify at a fixed `--at`, which always wins over any timestamp.
fn run_at(xml: &str, anchors: Vec<Vec<u8>>, time: &str) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339(time).expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(time.to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

/// Verify with no `--at` and the real clock, which is what lets a verified
/// timestamp move the validation time into the past.
fn run_now(xml: &str, anchors: Vec<Vec<u8>>) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = SystemClock;
    let options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

/// Every check, including the ones that belong to a token.
fn codes(report: &VerifyReport) -> Vec<String> {
    report
        .checks
        .iter()
        .chain(report.signatures.iter().flat_map(|signature| {
            signature.checks.iter().chain(
                signature
                    .timestamps
                    .iter()
                    .flat_map(|timestamp| timestamp.checks.iter()),
            )
        }))
        .map(|check| format!("{}={}", check.code.as_str(), check.status.as_str()))
        .collect()
}

fn assert_check(report: &VerifyReport, code: CheckCode, status: CheckStatus) {
    let seen = codes(report);
    assert!(
        seen.contains(&format!("{}={}", code.as_str(), status.as_str())),
        "expected {}={}; got {seen:?}",
        code.as_str(),
        status.as_str()
    );
}

/// A root, a signer, and a timestamp authority under the same root.
struct Pki {
    root_der: Vec<u8>,
    signer_der: Vec<u8>,
    signer_key: TestKey,
    tsa_der: Vec<u8>,
}

/// Build the synthetic PKI. `signer_expiry` is when the signing certificate
/// stops being valid, so a test can make it expire before "now".
fn pki(signer_expiry: (i32, u8, u8), tsa_eku: Option<(&str, bool)>) -> Pki {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut signer_spec = CertSpec::signer("openSzigno Test Signer");
    signer_spec.not_after = signer_expiry;
    let signer = issued_by(&signer_spec, &signer_key, &root, &root_key);

    let mut tsa_spec = CertSpec::signer("openSzigno Test TSA");
    if let Some((oid, critical)) = tsa_eku {
        tsa_spec.custom_extensions = vec![extended_key_usage_extension(&[oid], critical)];
    }
    let tsa = issued_by(&tsa_spec, &rsa_key(keys::THIRD_RSA2048), &root, &root_key);

    Pki {
        root_der: root.der,
        signer_der: signer.der,
        signer_key,
        tsa_der: tsa.der,
    }
}

fn good_pki() -> Pki {
    pki((2039, 1, 1), Some((ID_KP_TIME_STAMPING, true)))
}

/// A document signature carrying one timestamp built to `configure`.
fn signature_with_timestamp(pki: &Pki, configure: impl FnOnce(&mut TimestampSpec)) -> SigSpec {
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    let mut timestamp = TimestampSpec::new(
        rsa_key(keys::THIRD_RSA2048),
        pki.tsa_der.clone(),
        "2020-06-01T09:00:00Z",
    );
    configure(&mut timestamp);
    signature.timestamp = Some(timestamp);
    signature
}

fn dossier(signature: SigSpec, key: &TestKey) -> String {
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    build(&spec, &[("doc", key)])
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn a_correct_token_verifies_end_to_end() {
    let pki = good_pki();
    let xml = dossier(signature_with_timestamp(&pki, |_| {}), &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");

    assert_check(
        &report,
        CheckCode::TimestampTokenParsed,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::TimestampImprintOk, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::TimestampSignatureOk,
        CheckStatus::Passed,
    );
    assert_check(
        &report,
        CheckCode::TimestampTsaCertificateOk,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::TimestampTsaPathOk, CheckStatus::Passed);
    assert_check(&report, CheckCode::TimestampVerified, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::SignatureTimestampPresent,
        CheckStatus::Unknown,
    );

    let timestamp = &report.signatures[0].timestamps[0];
    assert!(timestamp.verified);
    assert_eq!(timestamp.gen_time.as_deref(), Some("2020-06-01T09:00:00Z"));
    assert_eq!(timestamp.imprint_algorithm, Some("sha256"));
    assert_eq!(timestamp.accuracy_seconds, Some(1));
    assert_eq!(
        timestamp
            .tsa_certificate
            .as_ref()
            .and_then(|summary| summary.subject_cn.clone()),
        Some("openSzigno Test TSA".to_owned())
    );
    // A verified timestamp proves existence, not validity: revocation is still
    // unchecked, so the verdict cannot be `valid`.
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// The token still verifies when the timestamp names inclusive C14N
/// explicitly, which is also the XAdES default.
#[test]
fn an_explicit_canonicalization_method_is_honoured() {
    let pki = good_pki();
    let signature = signature_with_timestamp(&pki, |timestamp| {
        timestamp.c14n = Some(common::C14N_INC.to_owned());
    });
    let xml = dossier(signature, &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");
    assert_check(&report, CheckCode::TimestampVerified, CheckStatus::Passed);
}

/// Exclusive C14N over `ds:SignatureValue` produces different octets from the
/// inclusive default, and the verifier must use the algorithm the timestamp
/// names rather than assuming one.
#[test]
fn an_exclusive_canonicalization_method_is_honoured() {
    let pki = good_pki();
    let signature = signature_with_timestamp(&pki, |timestamp| {
        timestamp.c14n = Some(common::C14N_EXC.to_owned());
    });
    let xml = dossier(signature, &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");
    assert_check(&report, CheckCode::TimestampVerified, CheckStatus::Passed);
}

// ---------------------------------------------------------------------------
// Negative cases
// ---------------------------------------------------------------------------

/// The imprint is the step that binds a token to *this* signature. A token
/// over other data must never be accepted, however well it is signed.
#[test]
fn a_token_over_other_data_fails_the_imprint() {
    let pki = good_pki();
    let signature = signature_with_timestamp(&pki, |timestamp| timestamp.wrong_imprint = true);
    let xml = dossier(signature, &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");

    assert_check(
        &report,
        CheckCode::TimestampImprintMismatch,
        CheckStatus::Failed,
    );
    assert_check(&report, CheckCode::TimestampVerified, CheckStatus::Failed);
    assert!(!report.signatures[0].timestamps[0].verified);
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// RFC 3161 requires the TSA certificate to carry a critical
/// `id-kp-timeStamping`, and a certificate without it cannot timestamp.
#[test]
fn a_tsa_without_the_timestamping_eku_fails() {
    let pki = pki((2039, 1, 1), None);
    let xml = dossier(signature_with_timestamp(&pki, |_| {}), &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");

    assert_check(
        &report,
        CheckCode::TimestampTsaCertificateInvalid,
        CheckStatus::Failed,
    );
    assert_check(&report, CheckCode::TimestampVerified, CheckStatus::Failed);
}

/// An `extendedKeyUsage` that is present but names another purpose is just as
/// unacceptable as none at all.
#[test]
fn a_tsa_with_the_wrong_eku_fails() {
    let pki = pki((2039, 1, 1), Some((ID_KP_EMAIL_PROTECTION, true)));
    let xml = dossier(signature_with_timestamp(&pki, |_| {}), &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");

    assert_check(
        &report,
        CheckCode::TimestampTsaCertificateInvalid,
        CheckStatus::Failed,
    );
}

/// The EKU must be *critical*: a non-critical one is a hint the issuer chose
/// not to enforce.
#[test]
fn a_tsa_whose_eku_is_not_critical_fails() {
    let pki = pki((2039, 1, 1), Some((ID_KP_TIME_STAMPING, false)));
    let xml = dossier(signature_with_timestamp(&pki, |_| {}), &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");

    assert_check(
        &report,
        CheckCode::TimestampTsaCertificateInvalid,
        CheckStatus::Failed,
    );
}

/// A TSA under a root nobody configured cannot move anything.
#[test]
fn a_tsa_chain_that_reaches_no_anchor_is_untrusted() {
    let pki = good_pki();
    let other_key = rsa_key(keys::SECOND_RSA2048);
    let other_root = self_signed(
        &CertSpec::ca("openSzigno Other Root", BasicConstraints::Unconstrained),
        &other_key,
    );
    let mut tsa_spec = CertSpec::signer("openSzigno Rogue TSA");
    tsa_spec.custom_extensions = vec![extended_key_usage_extension(&[ID_KP_TIME_STAMPING], true)];
    let rogue = issued_by(
        &tsa_spec,
        &rsa_key(keys::INTERMEDIATE_RSA2048),
        &other_root,
        &other_key,
    );

    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    let mut timestamp = TimestampSpec::new(
        rsa_key(keys::INTERMEDIATE_RSA2048),
        rogue.der.clone(),
        "2020-06-01T09:00:00Z",
    );
    timestamp.token_certificates = vec![other_root.der.clone()];
    signature.timestamp = Some(timestamp);
    let xml = dossier(signature, &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");

    assert_check(
        &report,
        CheckCode::TimestampTsaPathUntrusted,
        CheckStatus::Failed,
    );
    assert!(!report.signatures[0].timestamps[0].verified);
}

/// With no trust store there is nothing to say, and `unknown` is the honest
/// answer for a TSA chain just as for a signer chain.
#[test]
fn without_anchors_the_tsa_chain_is_unknown() {
    let pki = good_pki();
    let xml = dossier(signature_with_timestamp(&pki, |_| {}), &pki.signer_key);
    let trust = NoTrust;
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339("2020-06-02T00:00:00Z").expect("parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some("2020-06-02T00:00:00Z".to_owned());
    let report = verify(xml.as_bytes(), &options).expect("the dossier parses structurally");

    assert_check(
        &report,
        CheckCode::TimestampTsaPathUnknown,
        CheckStatus::Unknown,
    );
    assert_check(&report, CheckCode::TimestampVerified, CheckStatus::Unknown);
    assert!(!report.signatures[0].timestamps[0].verified);
    assert_ne!(report.verdict, Verdict::Valid);
}

/// A token that is not a CMS `SignedData` at all fails to parse, and the good
/// token in the same shape still verifies, so the difference is the token and
/// not the fixture.
#[test]
fn a_truncated_token_fails_to_parse() {
    let pki = good_pki();
    let xml = dossier(signature_with_timestamp(&pki, |_| {}), &pki.signer_key);
    // Drop the certificate set by truncating the token, which is also a
    // malformed-token case: either way it must not verify.
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");
    assert!(report.signatures[0].timestamps[0].verified);

    let signature = signature_with_timestamp(&pki, |timestamp| {
        timestamp.raw_token = Some(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
    });
    let broken = dossier(signature, &pki.signer_key);
    let report = run_at(&broken, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");
    assert_check(
        &report,
        CheckCode::TimestampTokenParsed,
        CheckStatus::Failed,
    );
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// Garbage in an `EncapsulatedTimeStamp` must be refused without panicking,
/// whatever shape it takes.
#[test]
fn garbage_tokens_never_panic() {
    let pki = good_pki();
    let payloads: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0xff; 64],
        vec![0x30, 0x80, 0x30, 0x80],
        (0u8..=255).collect(),
        vec![0x30, 0x82, 0xff, 0xff, 0x00],
    ];
    for payload in payloads {
        let signature = signature_with_timestamp(&pki, |timestamp| {
            timestamp.raw_token = Some(payload.clone());
        });
        let xml = dossier(signature, &pki.signer_key);
        let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");
        assert_check(
            &report,
            CheckCode::TimestampTokenParsed,
            CheckStatus::Failed,
        );
        assert_ne!(report.verdict, Verdict::Valid);
    }
}

/// A timestamp that selects its data with `xades:Include` uses a form this
/// build does not implement, and is reported as unchecked rather than verified
/// against the wrong bytes.
#[test]
fn an_unsupported_data_selection_form_is_not_checked() {
    let pki = good_pki();
    let signature = signature_with_timestamp(&pki, |timestamp| timestamp.include_element = true);
    let xml = dossier(signature, &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");

    assert_check(
        &report,
        CheckCode::TimestampNotChecked,
        CheckStatus::Skipped,
    );
    assert!(!report.signatures[0].timestamps[0].verified);
    assert_ne!(report.verdict, Verdict::Valid);
}

/// A `genTime` well before the claimed `SigningTime` is contradictory, but the
/// claim is unauthenticated, so it is reported as `unknown` and never as a
/// cryptographic failure.
#[test]
fn a_token_older_than_the_claimed_signing_time_is_unknown() {
    let pki = good_pki();
    let signature = signature_with_timestamp(&pki, |timestamp| {
        // The helper's `xades:SigningTime` is 2020-01-01T00:00:00Z.
        timestamp.gen_time = "2019-06-01T09:00:00Z".to_owned();
    });
    let xml = dossier(signature, &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");

    assert_check(
        &report,
        CheckCode::TimestampBeforeSigningTime,
        CheckStatus::Unknown,
    );
    assert_check(&report, CheckCode::TimestampVerified, CheckStatus::Unknown);
    // Reported, never treated as a failure: `SigningTime` is only a claim.
    assert_ne!(report.verdict, Verdict::Invalid);
}

// ---------------------------------------------------------------------------
// The validation time
// ---------------------------------------------------------------------------

/// The point of a signature timestamp: a signing certificate that expired
/// years ago still chains, because the path is validated at the token's
/// `genTime` rather than at "now".
#[test]
fn a_verified_token_moves_the_validation_time_into_the_past() {
    let pki = pki((2021, 1, 1), Some((ID_KP_TIME_STAMPING, true)));
    let xml = dossier(signature_with_timestamp(&pki, |_| {}), &pki.signer_key);
    let report = run_now(&xml, vec![pki.root_der.clone()]);

    assert_eq!(
        report.signatures[0].validation_time_source,
        ValidationTimeSource::Timestamp
    );
    assert_eq!(report.signatures[0].validation_time, "2020-06-01T09:00:00Z");
    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// Without a timestamp the same dossier fails on an expired certificate, which
/// is what makes the previous test mean something.
#[test]
fn without_a_timestamp_the_expired_signer_fails_now() {
    let pki = pki((2021, 1, 1), Some((ID_KP_TIME_STAMPING, true)));
    let xml = dossier(
        document_signature(vec![pki.signer_der.clone()]),
        &pki.signer_key,
    );
    let report = run_now(&xml, vec![pki.root_der.clone()]);

    assert_eq!(
        report.signatures[0].validation_time_source,
        ValidationTimeSource::CurrentTime
    );
    assert_check(&report, CheckCode::CertExpired, CheckStatus::Failed);
}

/// `--at` always wins: an operator asking "was this valid then?" must not be
/// silently answered about some other instant.
#[test]
fn the_at_flag_overrides_a_verified_token() {
    let pki = pki((2021, 1, 1), Some((ID_KP_TIME_STAMPING, true)));
    let xml = dossier(signature_with_timestamp(&pki, |_| {}), &pki.signer_key);
    let report = run_at(&xml, vec![pki.root_der.clone()], "2026-01-01T00:00:00Z");

    assert_eq!(
        report.signatures[0].validation_time_source,
        ValidationTimeSource::AtFlag
    );
    assert_eq!(report.signatures[0].validation_time, "2026-01-01T00:00:00Z");
    assert_check(&report, CheckCode::CertExpired, CheckStatus::Failed);
}

/// A token that did not fully verify must not move the validation time; a
/// timestamp nobody could check is not proof of anything.
#[test]
fn an_unverified_token_does_not_move_the_validation_time() {
    let pki = pki((2021, 1, 1), Some((ID_KP_TIME_STAMPING, true)));
    let signature = signature_with_timestamp(&pki, |timestamp| timestamp.wrong_imprint = true);
    let xml = dossier(signature, &pki.signer_key);
    let report = run_now(&xml, vec![pki.root_der.clone()]);

    assert_eq!(
        report.signatures[0].validation_time_source,
        ValidationTimeSource::CurrentTime
    );
    assert_check(&report, CheckCode::CertExpired, CheckStatus::Failed);
}

/// A timestamp with no decodable token, one with two tokens, and one naming a
/// canonicalization algorithm this build does not implement are all reported
/// as unchecked, never as verified.
#[test]
fn timestamp_shapes_this_build_does_not_process_are_not_checked() {
    let pki = good_pki();
    // Which shape to build: no decodable token, two tokens, or a
    // canonicalization algorithm this build does not implement.
    let variants = ["undecodable", "duplicate", "c14n11"];
    for variant in variants {
        let signature = signature_with_timestamp(&pki, |timestamp| match variant {
            "undecodable" => timestamp.undecodable_token = true,
            "duplicate" => timestamp.duplicate_token = true,
            // Canonical XML 1.1, which this build refuses rather than
            // approximates.
            _ => timestamp.c14n = Some("http://www.w3.org/2006/12/xml-c14n11".to_owned()),
        });
        let xml = dossier(signature, &pki.signer_key);
        let report = run_at(&xml, vec![pki.root_der.clone()], "2020-06-02T00:00:00Z");
        assert_check(
            &report,
            CheckCode::TimestampNotChecked,
            CheckStatus::Skipped,
        );
        assert!(!report.signatures[0].timestamps[0].verified);
        assert_ne!(report.verdict, Verdict::Valid);
    }
}
