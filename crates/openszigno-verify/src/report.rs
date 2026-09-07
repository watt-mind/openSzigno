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

/// What is known about one modelled document's signature coverage.
///
/// Coverage is a statement about *what a signature's resolved references
/// include*, never about where the signature sits. It is deliberately kept
/// apart from the cryptographic outcome: a document can be covered by a
/// signature that does not verify, and the two facts are reported separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    /// At least one covering signature's own verdict is `valid`.
    Covered,
    /// Covered, but only by signatures whose verdict is `invalid` or
    /// `indeterminate`. The `reason` names the best verdict among them.
    CoveredUnverified,
    /// No signature covers this document under the e-dossier scope rules.
    Uncovered,
    /// A signature that might cover this document could not be evaluated:
    /// an unsupported transform, an unresolved reference, a placement the
    /// format does not describe, or a structural failure.
    Undetermined,
    /// The core parser skipped this `es:Document` because it carries no
    /// `es:DocumentProfile`, so it is not one of the modelled documents and
    /// the mandated reference set for it is undefined. The `reason` is the
    /// parser's own warning.
    NotModelled,
}

impl CoverageState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::CoveredUnverified => "covered_unverified",
            Self::Uncovered => "uncovered",
            Self::Undetermined => "undetermined",
            Self::NotModelled => "not_modelled",
        }
    }
}

/// How a signature reaches a document.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageVia {
    /// A document-level signature placed in this `es:Document`, whose
    /// reference scope is complete and whose references resolve to this
    /// document's `es:DocumentProfile` and payload `ds:Object`.
    Direct,
    /// A dossier-level signature with a complete reference scope whose
    /// references resolve to `es:Documents`, or to an ancestor of it.
    Frame,
}

/// One signature that covers a document, with its own verdict.
#[derive(Clone, Debug, Serialize)]
pub struct CoveringSignature {
    /// The index into `data.signatures`.
    pub signature_index: usize,
    pub via: CoverageVia,
    /// That signature's own verdict. Coverage does not change it, and it does
    /// not change coverage.
    pub verdict: Verdict,
}

/// The signature coverage of one `es:Document`, in source order.
#[derive(Clone, Debug, Serialize)]
pub struct DocumentCoverage {
    /// The index the structural model gives this document, or `null` for a
    /// document the parser did not model.
    pub index: Option<usize>,
    /// The `OBJREF` of the document's payload object, or `null` when the
    /// document was not modelled. Never a title.
    pub object_ref: Option<String>,
    /// The declared type marks this document as an embedded dossier. Its own
    /// inner signatures are **not** verified by this run.
    pub nested_dossier: bool,
    pub coverage: CoverageState,
    /// Every signature that covers this document, in signature order.
    pub covered_by: Vec<CoveringSignature>,
    /// Why the state is what it is, when there is something to say. Never a
    /// title, a path, or payload content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Counts {
    pub signatures: usize,
    pub signatures_valid: usize,
    pub signatures_invalid: usize,
    pub signatures_indeterminate: usize,
    /// Container timestamps present: every `es:TimeStamp` the dossier carries.
    pub timestamps: usize,
    /// How many of those were fully verified — imprint, TSA signature,
    /// `id-kp-timeStamping`, and a path to a configured anchor at `genTime`.
    pub timestamps_verified: usize,
    /// Modelled documents whose coverage state is `covered`.
    pub documents_covered: usize,
    /// Modelled documents whose coverage state is `uncovered`.
    pub documents_uncovered: usize,
    /// Modelled documents whose coverage state is `undetermined`.
    ///
    /// The three document counts name the states of the same name only. A
    /// `covered_unverified` or `not_modelled` document is in `data.documents`
    /// and in none of them, because neither is an answer to "is this content
    /// signed" that any of the three states gives.
    pub documents_undetermined: usize,
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
    /// Whether this signature's certificate chain is qualified under eIDAS.
    ///
    /// `true` only when the chain ends at an anchor an ETSI TS 119 612 trusted
    /// list lists as a granted CA/QC service at the validation time **and**,
    /// for a certificate issued after eIDAS applied, the certificate itself
    /// asserts `QcCompliance`. `false` when a trusted list says the answer is
    /// no. `null` — never `false` — when no trusted list was consulted: "not
    /// determined" and "determined not to be qualified" are different answers.
    pub qualified: Option<bool>,
    /// Whether the signing certificate claims a qualified signature creation
    /// device (`QcSSCD`/QSCD). Only meaningful alongside `qualified: true`.
    pub qualified_signature_device: Option<bool>,
    /// The name of the trusted-list CA/QC service the chain matched, when one
    /// did. A service name is public information a caller needs in order to
    /// check the determination against the list themselves.
    pub qualified_service: Option<String>,
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
    /// Every container-level `es:TimeStamp`, dossier and document alike, each
    /// with its own checks. These decide nothing about any signature.
    pub timestamps: Vec<TimestampReport>,
    /// Every `es:Document` the container holds, in source order, with the
    /// signatures that cover it. See the architecture document's "Document
    /// coverage" section.
    pub documents: Vec<DocumentCoverage>,
    pub signatures: Vec<SignatureReport>,
}
