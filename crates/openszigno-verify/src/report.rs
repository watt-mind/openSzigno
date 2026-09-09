//! The serde types behind `verify --json`.

use serde::Serialize;

use crate::certs::{CertificateSummary, ChainEntry};
use crate::codes::{Check, CheckCode, CheckStatus, Verdict};
use crate::policy::{PolicyReport, VerifyLimits};
use crate::trust::{TimeSource, UnixTime, parse_rfc3339};
use crate::tsa::TimestampReport;
use crate::xades::{SignaturePolicy, SignaturePolicyDigest, SigningCertificateForm};

/// Where a signature sits in the container, which decides which elements it
/// must cover.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScope {
    /// `//es:Document/ds:Signature`.
    Document,
    /// `//es:Dossier/ds:Signature`, the frame signature.
    Dossier,
    /// A `ds:Signature` that is the only child of an `xades:CounterSignature`
    /// inside another signature's `xades:UnsignedSignatureProperties`, as
    /// ETSI EN 319 132-1 clause 5.2.7.2 and TS 101903 clause 7.2.4.2 define
    /// it. It attests the enclosing signature's `ds:SignatureValue`, never
    /// the payload.
    Countersignature,
    /// Anywhere else, which the e-dossier placement rules do not describe.
    /// This is the *unsupported placement* state: the signature is reported
    /// with `sig_placement_invalid` and a message naming the reason, and its
    /// verdict is deliberately kept out of the dossier verdict, because
    /// incomplete support is not evidence of forgery.
    Unknown,
}

/// Whether a signature stands on its own or attests another signature.
///
/// The role is orthogonal to the placement: a countersignature reaches the
/// container in two shapes. The XAdES one nests inside the countersigned
/// signature (`placement: countersignature`), and the e-dossier one is an
/// ordinary document- or dossier-level signature whose signed
/// `es:SignatureProfile/es:Type` says `countersignature` and whose references
/// include another signature's `ds:SignatureValue`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureRole {
    /// An ordinary signature over container content.
    Signature,
    /// A signature whose subject is another signature's `ds:SignatureValue`.
    Countersignature,
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
    /// The digest the explicit policy declares for its own policy document,
    /// when it declares one. Reported so a reader can check the policy by
    /// hand; nothing here is fetched or compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_policy_digest: Option<SignaturePolicyDigest>,
    /// The `xades:ClaimedRole` values of `SignerRole`/`SignerRoleV2`, as
    /// claimed. Hungarian AVDH signatures state the authenticated citizen
    /// here. Reported, never validated, and left out when there are none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claimed_roles: Vec<String>,
    /// The `xades:CommitmentTypeIndication` identifiers, as claimed. Reported,
    /// never applied, and left out when there are none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub commitment_type_ids: Vec<String>,
    pub signature_timestamps: usize,
    pub archive_timestamps: usize,
    /// Qualifying properties present in the signature that this build does not
    /// validate, by element name.
    pub unvalidated_properties: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SignatureReport {
    pub index: usize,
    /// The placement, under its original field name.
    ///
    /// Kept as an alias of [`SignatureReport::placement`] so no consumer of
    /// the phase-3 report breaks; both fields always carry the same value.
    pub scope: SignatureScope,
    /// Where this signature sits: `document`, `dossier`, `countersignature`,
    /// or `unknown` for a nesting this build does not support.
    pub placement: SignatureScope,
    /// Whether this signature attests container content or another signature.
    pub role: SignatureRole,
    /// The index into `data.signatures` of the signature this one is embedded
    /// in, for a `countersignature` placement. `null` otherwise, including for
    /// an e-dossier-form countersignature, which is a sibling and not nested.
    pub parent_signature_index: Option<usize>,
    /// The indexes into `data.signatures` of every signature whose
    /// `ds:SignatureValue` this signature's references resolve to. Empty for
    /// an ordinary signature.
    pub countersigns: Vec<usize>,
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

impl VerifyReport {
    /// Every certificate on a certification path this run **validated to a
    /// configured trust anchor**, for a signature or a timestamp it was
    /// actually evaluating.
    ///
    /// It exists for one caller: the CLI's `--online` fetcher, which may
    /// contact a CRL distribution point or an OCSP responder only for a
    /// certificate in this set. The narrower the set, the smaller the answer
    /// to "what can a dossier make this machine connect to" — and this is the
    /// narrowest honest answer available, because it is drawn from the paths
    /// the verifier built rather than from the certificates the file happens
    /// to carry. A certificate embedded somewhere else in the XML, however
    /// well signed, is not in it and cannot make anything be fetched.
    ///
    /// Only a chain whose own path check **passed** contributes: `cert_path_ok`
    /// for a signer, `timestamp_tsa_path_ok` for a timestamp authority. A path
    /// that was merely attempted is not a path the run validated.
    ///
    /// This is the set without its times.
    /// [`Self::validated_path_certificates_at`] is the same set with the
    /// validation time each path was evaluated at, which is what a caller
    /// needs in order to ask whether a certificate is *already covered*.
    pub fn validated_path_certificates(&self) -> Vec<Vec<u8>> {
        let mut certificates: Vec<Vec<u8>> = Vec::new();
        for (der, _) in self.validated_path_certificates_at() {
            if !certificates.contains(&der) {
                certificates.push(der);
            }
        }
        certificates
    }

    /// The same certificates, each paired with the validation time the
    /// verifier actually used for the path it sat on.
    ///
    /// A path is not evaluated at one global instant. A signer path backed by
    /// a verified signature timestamp is evaluated at that token's `genTime`
    /// — the proof of existence — and a timestamp authority's own path at the
    /// `genTime` it asserts, while everything else is evaluated at `--at` or
    /// at the clock. "Is this certificate already covered by revocation data?"
    /// therefore has a different answer per path, and asking it at one global
    /// time either fetches for a certificate a run already covers or skips one
    /// it does not.
    ///
    /// The same certificate can appear more than once, with a different time
    /// each time, when it sits on more than one validated path. Every entry is
    /// a time at which the run needs an answer about it.
    ///
    /// A path whose validation time cannot be read back, a timestamp with no
    /// `genTime` or an unparsable one, contributes nothing: a certificate may
    /// only be fetched for at a time this run can name.
    pub fn validated_path_certificates_at(&self) -> Vec<(Vec<u8>, UnixTime)> {
        let mut certificates: Vec<(Vec<u8>, UnixTime)> = Vec::new();
        let mut take = |chain: &[crate::certs::ChainEntry], validated: bool, time: Option<i64>| {
            let Some(time) = time.filter(|_| validated) else {
                return;
            };
            for entry in chain {
                let candidate = (entry.der.clone(), time);
                if !entry.der.is_empty() && !certificates.contains(&candidate) {
                    certificates.push(candidate);
                }
            }
        };
        for signature in &self.signatures {
            take(
                &signature.chain,
                passed(&signature.checks, CheckCode::CertPathOk),
                parse_rfc3339(&signature.validation_time),
            );
            for timestamp in &signature.timestamps {
                take(
                    &timestamp.chain,
                    passed(&timestamp.checks, CheckCode::TimestampTsaPathOk),
                    timestamp.gen_time.as_deref().and_then(parse_rfc3339),
                );
            }
        }
        for timestamp in &self.timestamps {
            take(
                &timestamp.chain,
                passed(&timestamp.checks, CheckCode::TimestampTsaPathOk),
                timestamp.gen_time.as_deref().and_then(parse_rfc3339),
            );
        }
        certificates
    }
}

/// Whether a set of checks carries this code with a `passed` status.
fn passed(checks: &[Check], code: CheckCode) -> bool {
    checks
        .iter()
        .any(|check| check.code == code && check.status == CheckStatus::Passed)
}
