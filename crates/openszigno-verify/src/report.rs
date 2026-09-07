//! The serde types behind `verify --json`.

use serde::Serialize;

use crate::certs::{CertificateSummary, ChainEntry};
use crate::codes::{Check, CheckStatus, Verdict};
use crate::policy::{PolicyReport, VerifyLimits};
use crate::trust::TimeSource;
use crate::tsa::TimestampReport;
use crate::xades::{SignaturePolicy, SigningCertificateForm};

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

/// Where the validation time used for one signature's certificate path came
/// from.
///
/// The precedence is fixed: an explicit `--at` always wins, then the earliest
/// fully verified signature timestamp's `genTime`, then the current time. A
/// timestamp moves the validation time only when *every* check on its token
/// passed, path to a trust anchor included.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationTimeSource {
    /// The `genTime` of a verified signature timestamp.
    Timestamp,
    /// The `--at` value the caller gave.
    AtFlag,
    /// The system clock.
    CurrentTime,
}

/// What the signed `SigningCertificate` property bound, and how.
#[derive(Clone, Debug, Serialize)]
pub struct SigningCertificateBinding {
    /// `v1` for `xades:SigningCertificate`, `v2` for `SigningCertificateV2`.
    pub form: Option<SigningCertificateForm>,
    pub digest_algorithm: Option<&'static str>,
    /// Whether the property also carried an `IssuerSerial`/`IssuerSerialV2`.
    pub issuer_serial_present: bool,
    /// Whether an offered certificate matched the digest.
    pub matched: bool,
}

/// The XAdES qualifying properties of one signature, as read.
#[derive(Clone, Debug, Serialize)]
pub struct XadesReport {
    pub present: bool,
    /// The claimed `xades:SigningTime`, repeated here so the XAdES view is
    /// self-contained.
    pub signing_time: Option<String>,
    pub signing_certificate: Option<SigningCertificateBinding>,
    pub signature_policy: Option<SignaturePolicy>,
    /// The explicit policy's identifier, sanitised. No policy is processed.
    pub signature_policy_id: Option<String>,
    pub signature_timestamps: usize,
    pub archive_timestamps: usize,
    /// Qualifying properties present in the signature that this build does not
    /// validate, by element name.
    pub unvalidated_properties: Vec<String>,
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
    pub xades: XadesReport,
    /// Every RFC 3161 token this signature carries, with its own checks.
    pub timestamps: Vec<TimestampReport>,
    /// The validation time actually used for this signature's certificate
    /// path, RFC 3339 UTC.
    pub validation_time: String,
    pub validation_time_source: ValidationTimeSource,
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
