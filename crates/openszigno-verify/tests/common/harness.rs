//! The end-to-end verification harness the `verify*` suites share: a run over
//! a synthetic dossier with or without a trust store, the check-code
//! assertions, and the small PKI those suites sign with.
//!
//! It lives here so that `verify.rs` and `verify_scope.rs` exercise exactly
//! the same harness rather than two copies of it.

use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{
    FixedClock, MemoryTrustStore, NoRevocation, NoTrust, RoxmltreeC14n, VerifyOptions,
    VerifyReport, parse_rfc3339, verify,
};
use rcgen::BasicConstraints;

use super::keys;
use super::pki::{CertSpec, TestKey, issued_by, rsa_key, self_signed};

/// A fixed validation time inside every synthetic certificate's window, so no
/// test depends on the wall clock.
pub fn at(text: &str) -> FixedClock {
    FixedClock(parse_rfc3339(text).expect("the fixed time parses"))
}

pub fn run(xml: &str, anchors: Vec<Vec<u8>>, time: &str) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = at(time);
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(time.to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

pub fn run_without_trust(xml: &str, time: &str) -> VerifyReport {
    let trust = NoTrust;
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = at(time);
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(time.to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

/// Every check code emitted anywhere in the report, with its status.
pub fn codes(report: &VerifyReport) -> Vec<(CheckCode, CheckStatus)> {
    report
        .checks
        .iter()
        .chain(
            report
                .signatures
                .iter()
                .flat_map(|signature| signature.checks.iter()),
        )
        .map(|check| (check.code, check.status))
        .collect()
}

pub fn has(report: &VerifyReport, code: CheckCode, status: CheckStatus) -> bool {
    codes(report).contains(&(code, status))
}

pub fn assert_check(report: &VerifyReport, code: CheckCode, status: CheckStatus) {
    assert!(
        has(report, code, status),
        "expected {} to be {}; got {:?}",
        code.as_str(),
        status.as_str(),
        codes(report)
            .iter()
            .map(|(code, status)| format!("{}={}", code.as_str(), status.as_str()))
            .collect::<Vec<_>>()
    );
}

pub fn assert_no_failures(report: &VerifyReport) {
    let failed: Vec<&str> = codes(report)
        .iter()
        .filter(|(_, status)| *status == CheckStatus::Failed)
        .map(|(code, _)| code.as_str())
        .collect();
    assert!(failed.is_empty(), "unexpected failures: {failed:?}");
}

/// A root and a signer, plus the keys behind them.
pub struct Pki {
    /// Kept so a test can issue further certificates from the same root.
    pub root_key: TestKey,
    pub signer_key: TestKey,
    pub root_der: Vec<u8>,
    pub signer_der: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
}

pub fn simple_pki() -> Pki {
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
    Pki {
        chain: vec![signer.der.clone()],
        root_der: root.der,
        signer_der: signer.der,
        root_key,
        signer_key,
    }
}
