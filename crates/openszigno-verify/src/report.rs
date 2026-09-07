//! The serde types behind `verify --json`.

use serde::Serialize;

use crate::certs::{CertificateSummary, ChainEntry};
use crate::codes::{Check, CheckStatus, Verdict};
use crate::policy::{PolicyReport, VerifyLimits};
use crate::trust::TimeSource;

/// Where a signature sits in the container, which decides which elements it
/// must cover.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScope {
    /// `//es:Document/ds:Signature`.
    Document,
    /// `//es:Dossier/ds:Signature`, the frame signature.
    Dossier,
    /// Anywhere else, which the e-dossier placement rules do not describe.
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerificationTime {
    /// The `--at` value as the caller wrote it, or `null`.
    pub requested: Option<String>,
    pub effective: String,
    pub source: TimeSource,
}

#[derive(Clone, Debug, Serialize)]
pub struct Counts {
    pub signatures: usize,
    pub signatures_valid: usize,
    pub signatures_invalid: usize,
    pub signatures_indeterminate: usize,
    pub timestamps: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReferenceReport {
    pub index: usize,
    pub uri: String,
    /// A path of element names, never content: `Dossier/Documents/Document[0]`.
    pub resolved_to: Option<String>,
    pub digest_algorithm: Option<String>,
    pub transforms: Vec<String>,
    pub status: CheckStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct SignatureReport {
    pub index: usize,
    pub scope: SignatureScope,
    pub document_index: Option<usize>,
    pub signature_id: Option<String>,
    pub verdict: Verdict,
    /// Detected, not validated, in phase 1.
    pub xades_level: Option<&'static str>,
    /// The `xades:SigningTime` the signature *claims*, normalised to RFC 3339
    /// UTC, or `null` when absent or unparseable.
    ///
    /// It is read, never trusted: it is unauthenticated until a verified
    /// timestamp token binds it, which is phase 2. It never becomes the
    /// validation time; only `--at` and the clock do that.
    pub signing_time: Option<String>,
    /// Which `ds:KeyInfo` certificate verified the signature, counted from
    /// zero in document order, or `null` when none did.
    pub signing_certificate_index: Option<usize>,
    pub signing_certificate: Option<CertificateSummary>,
    pub chain: Vec<ChainEntry>,
    pub references: Vec<ReferenceReport>,
    /// Always empty in phase 1; timestamps are phase 2.
    pub timestamps: Vec<()>,
    pub checks: Vec<Check>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerifyReport {
    pub verdict: Verdict,
    pub verification_time: VerificationTime,
    pub policy: PolicyReport,
    pub limits: VerifyLimits,
    pub counts: Counts,
    /// Checks that belong to the dossier rather than to one signature.
    pub checks: Vec<Check>,
    pub signatures: Vec<SignatureReport>,
}
