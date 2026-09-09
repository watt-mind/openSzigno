//! Stage E: revocation, offline first.
//!
//! Every byte of revocation data arrives through the injected
//! [`RevocationSource`](crate::trust::RevocationSource) or out of the
//! signature's own `xades:RevocationValues`. This module opens no socket and
//! no file; fetching, when a caller wants it, belongs to the CLI.
//!
//! # What is checked
//!
//! CRLs follow RFC 5280 section 6.3 and OCSP responses follow RFC 6960, in
//! both cases with a deliberately narrow implemented subset and every
//! unimplemented form refused rather than half-handled:
//!
//! - **Issuer.** A CRL's `issuer` must equal the certificate's `issuer`.
//!   Indirect CRLs are refused, so a CRL never speaks for a CA that did not
//!   issue it.
//! - **Signature.** The CRL or OCSP response must verify under the pinned
//!   algorithm allowlist against the issuing CA's key, or against a properly
//!   authorised delegate: a CRL signer whose certificate the CA issued and
//!   which asserts `cRLSign`, or an OCSP responder whose certificate the CA
//!   issued and which carries `id-kp-OCSPSigning`.
//! - **Scope.** A CRL carrying an `issuingDistributionPoint` is accepted only
//!   in the forms this module implements; a delta CRL, an indirect CRL, a
//!   partitioned CRL naming a distribution point the certificate does not,
//!   and a scope restricted to reasons or attribute certificates are all
//!   refused. Any other critical CRL extension is refused too.
//! - **Freshness.** Data whose `nextUpdate` is at or before the validation
//!   time is *stale*: a newer CRL or response may carry a revocation this one
//!   predates, so believing it would be believing an answer to a different
//!   question. There is **no grace period**: a grace period is a decision to
//!   accept data that has expired, which is exactly the decision a verifier
//!   must not make silently. Data with no `nextUpdate` at all is usable only
//!   when its `thisUpdate` is at or after the validation time, where it is a
//!   statement about a moment no earlier than the one being asked about.
//! - **Time of revocation.** A revocation counts only when its
//!   `revocationTime` is at or before the validation time. A certificate
//!   revoked *after* the instant being validated was not revoked then, so it
//!   yields the distinct, non-fatal
//!   [`CertRevokedAfterValidationTime`](crate::codes::CheckCode::CertRevokedAfterValidationTime)
//!   rather than `cert_revoked`; it is `unknown`, not `passed`, because a
//!   later revocation is a reason to look harder, not a clean bill of health.
//! - **`certificateHold`.** Treated as revoked. A suspended certificate is
//!   not a usable one.
//! - **Agreement between sources.** Every source is asked about every
//!   certificate, and a revocation from any of them beats `good` from any
//!   other. The tier order decides only which source is *read* first, never
//!   which answer wins: the signature's own `RevocationValues` are supplied by
//!   the signer, so a first-answer-wins rule let a genuine but older embedded
//!   OCSP `good` hide the operator's newer CRL revoking the same certificate.
//!   A disagreement is reported as `revocation_sources_disagree` (`info`).
//!
//! # What is not checked
//!
//! The OCSP nonce is ignored, because offline validation replays a response
//! that was produced for someone else's request; a nonce could never match and
//! demanding one would make every archived response unusable. Freshness and
//! the `certID` binding carry the weight instead.
//!
//! The module is split by what each part validates: `crl` holds CRL
//! validation and lookup, `ocsp` holds OCSP response validation and the
//! responder-authorisation models, and `tiers` holds the source gathering,
//! the fallback rules, and the summaries and messages a path's answers become.
//! What stays here is the public API, the per-path driver, and the store
//! classification the CLI loads through.

mod crl;
mod ocsp;
#[cfg(test)]
mod tests;
mod tiers;

pub use ocsp::{ResponderModel, ocsp_cert_id, ocsp_request};
pub use tiers::RevocationOrigin;

use const_oid::ObjectIdentifier;
use der::Decode;
use serde::Serialize;
use x509_cert::crl::CertificateList;
use x509_ocsp::{BasicOcspResponse, OcspResponse};

use crate::certs::ParsedCertificate;
use crate::codes::{Check, CheckCode};
use crate::policy::VerifyLimits;
use crate::trust::{RevocationPolicy, UnixTime};

use tiers::{check_certificate, summarise};

const OID_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
use crate::certs::OID_KP_OCSP_SIGNING;

/// What was concluded about one certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    /// Fresh, verified data says the certificate was not revoked.
    Good,
    /// The certificate was revoked at or before the validation time.
    Revoked,
    /// The certificate was revoked, but *after* the validation time, so the
    /// revocation did not apply at the instant being asked about.
    RevokedAfterValidationTime,
    /// Nothing usable was found, or what was found does not answer the
    /// question that was asked.
    Unknown,
    /// The caller switched revocation checking off.
    NotChecked,
    /// This certificate is a trust anchor, whose revocation is not a question
    /// a relying party can answer from the PKI itself.
    TrustAnchor,
}

/// One certificate's revocation answer, as it appears in the report.
#[derive(Clone, Debug, Serialize)]
pub struct CertificateRevocation {
    pub status: RevocationStatus,
    /// The check code that summarises this certificate.
    pub code: &'static str,
    pub source: Option<RevocationOrigin>,
    /// RFC 3339 UTC, when the data said the certificate was revoked.
    pub revocation_time: Option<String>,
    /// The RFC 5280 reason code, lower-cased, when one was given.
    pub reason: Option<&'static str>,
    pub this_update: Option<String>,
    pub next_update: Option<String>,
    /// OCSP only.
    pub produced_at: Option<String>,
    /// OCSP only: which RFC 6960 model authorised the responder that answered.
    pub responder_model: Option<ResponderModel>,
    /// A sentence about data that was consulted and could not be used: why an
    /// answer was refused, and — when a later source answered instead — which
    /// one did. Present on an entry that ended `unknown` *and* on one that
    /// succeeded after something earlier was refused, because "a CRL saved
    /// this" is exactly what an operator debugging an OCSP responder needs to
    /// be told.
    pub detail: Option<String>,
}

impl CertificateRevocation {
    pub(super) fn plain(status: RevocationStatus, code: CheckCode) -> Self {
        Self {
            status,
            code: code.as_str(),
            source: None,
            revocation_time: None,
            reason: None,
            this_update: None,
            next_update: None,
            produced_at: None,
            responder_model: None,
            detail: None,
        }
    }

    /// The entry for a trust anchor, which is never asked about.
    pub fn trust_anchor() -> Self {
        Self::plain(
            RevocationStatus::TrustAnchor,
            CheckCode::RevocationNotChecked,
        )
    }

    /// The entry emitted when the caller passed `--no-revocation`.
    pub fn not_checked() -> Self {
        Self::plain(
            RevocationStatus::NotChecked,
            CheckCode::RevocationNotChecked,
        )
    }
}

/// The revocation material offered to one path, already separated by origin so
/// that the report can say where an answer came from.
#[derive(Clone, Copy, Debug, Default)]
pub struct RevocationData<'a> {
    pub embedded_crls: &'a [Vec<u8>],
    pub embedded_ocsp: &'a [Vec<u8>],
    pub store_crls: &'a [Vec<u8>],
    pub store_ocsp: &'a [Vec<u8>],
    /// Artefacts the CLI fetched under `--online`. They are consulted last and
    /// checked by exactly the same code as any offline item: fetching from a
    /// URL a certificate published is a way of *obtaining* data, never a
    /// reason to believe it.
    pub online_crls: &'a [Vec<u8>],
    pub online_ocsp: &'a [Vec<u8>],
}

impl RevocationData<'_> {
    pub(super) fn is_empty(&self) -> bool {
        self.embedded_crls.is_empty()
            && self.embedded_ocsp.is_empty()
            && self.store_crls.is_empty()
            && self.store_ocsp.is_empty()
            && self.online_crls.is_empty()
            && self.online_ocsp.is_empty()
    }
}

/// Which chain is being asked about.
///
/// A signature carries at least two — its signer's and each timestamp
/// authority's — and both report through the same code, so the message has to
/// say which one it is about or the duplicate is unreadable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainRole {
    Signer,
    TimestampAuthority,
}

impl ChainRole {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Signer => "the signing certificate's chain",
            Self::TimestampAuthority => "the timestamp authority's chain",
        }
    }
}

/// Everything one path's revocation check needs.
pub struct PathRevocationInput<'a> {
    /// The validated path, end-entity first and trust anchor last.
    pub path: &'a [ParsedCertificate],
    /// Untrusted certificates offered as CRL signers and OCSP responders.
    pub candidates: &'a [ParsedCertificate],
    /// The configured trust anchors, which are what the RFC 6960 section 2.2
    /// "trusted responder" model rests on. Nothing else in this module uses
    /// them: a CRL signer and a delegated responder are authorised by the
    /// issuing CA, not by the caller's store.
    pub anchors: &'a [ParsedCertificate],
    pub data: &'a RevocationData<'a>,
    pub time: UnixTime,
    /// Whether the validation time is *proven* — that is, whether it came from
    /// a fully verified timestamp token rather than from `--at` or the clock.
    ///
    /// It decides only one thing: whether a revocation dated after that time
    /// may be dismissed. See [`check_path`].
    pub time_is_proven: bool,
    pub policy: RevocationPolicy,
    pub role: ChainRole,
    pub limits: &'a VerifyLimits,
}

/// The revocation outcome for a whole path.
pub struct PathRevocation {
    /// One entry per certificate in the path, in the same order.
    pub per_certificate: Vec<CertificateRevocation>,
    /// The single check the path contributes to the signature's verdict.
    pub check: Check,
    /// Informational checks about *how* an answer was obtained, which report
    /// rather than decide and so never block: `ocsp_responder_trusted`,
    /// emitted when a response was accepted under the RFC 6960 section 2.2
    /// trusted-responder model, because that rests on the caller's own trust
    /// store rather than on the issuing CA's word and a reader is entitled to
    /// know which it was; and `revocation_sources_disagree`, emitted when the
    /// usable sources for one certificate did not say the same thing.
    pub notes: Vec<Check>,
}

/// The clause every `revocation_status_unknown` carries when `--online` was
/// asked for and could fetch nothing, because no trust anchor was configured
/// and revocation data is only fetched for a certificate on a path to one.
///
/// It is repeated on each such message rather than left to the policy check
/// alone: the reader of *this* sentence is the one who has to decide what to
/// do about the gap, and "nothing was fetched" without "and here is why" is
/// the report this ticket exists to fix.
fn unfetched(policy: RevocationPolicy) -> &'static str {
    match policy {
        RevocationPolicy::OnlineNoAnchors => {
            ", and --online fetched nothing because no trust anchors are configured, so no certificate sits on a path to one"
        }
        RevocationPolicy::NotChecked | RevocationPolicy::Offline | RevocationPolicy::Online => "",
    }
}

/// The check that reports the policy actually applied, so the machine output
/// shows it whether or not any data was found.
pub fn policy_check(policy: RevocationPolicy) -> Check {
    match policy {
        RevocationPolicy::NotChecked => Check::info(
            CheckCode::RevocationPolicy,
            "revocation checking is switched off, which caps the verdict at indeterminate",
        ),
        RevocationPolicy::Offline => Check::info(
            CheckCode::RevocationPolicy,
            "revocation is checked offline, from the signature's own RevocationValues and the revocation store",
        ),
        RevocationPolicy::Online => Check::info(
            CheckCode::RevocationPolicy,
            "revocation is checked from the signature's own RevocationValues and the revocation store first, and --online allowed CRL distribution points and AIA OCSP responders named by the certificates themselves to be fetched for what they did not cover, but only for certificates on a path to a configured trust anchor; every fetched artefact was checked by the same offline rules",
        ),
        RevocationPolicy::OnlineNoAnchors => Check::info(
            CheckCode::RevocationPolicy,
            "--online was given but no trust anchors were configured, so nothing was fetched and revocation was checked offline: a URL is only contacted for a certificate that sits on a path to a configured trust anchor, and without anchors no certificate does. Configure --trust-store or --trust-list to allow fetching",
        ),
    }
}

/// Whether offline material already answers `good` for one certificate.
///
/// This is the question `--online` asks before it fetches anything: online
/// data may only *add* to what is already to hand, so the CLI consults the
/// very same code path the verdict will use rather than a cheaper
/// approximation of it. A certificate that is already covered is never
/// fetched for, which is what keeps `--online` from broadcasting a request for
/// every dossier a caller opens.
pub fn is_covered(
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    data: &RevocationData<'_>,
    time: UnixTime,
    limits: &VerifyLimits,
) -> bool {
    is_covered_at(
        subject,
        issuer,
        candidates,
        anchors,
        crate::certs::AnchorStatus::none(),
        data,
        time,
        limits,
    )
}

/// [`is_covered`], told what the caller knows about each anchor.
///
/// `status` reaches only the RFC 6960 section 2.2 trusted-responder model,
/// which validates a responder's own path to an anchor. Deciding what to fetch
/// is planning rather than verification: whatever this answers, the same code
/// runs again, with the same status, when the verdict is made.
#[allow(clippy::too_many_arguments)]
pub fn is_covered_at(
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    status: crate::certs::AnchorStatus<'_>,
    data: &RevocationData<'_>,
    time: UnixTime,
    limits: &VerifyLimits,
) -> bool {
    matches!(
        check_certificate(
            subject, issuer, candidates, anchors, status, data, time, limits
        )
        .entry
        .status,
        RevocationStatus::Good | RevocationStatus::Revoked
    )
}

/// Check every certificate in `path` except the trust anchor.
///
/// `path[0]` is the end-entity certificate and the last element is the anchor.
/// The anchor is skipped on purpose: its revocation is not something the PKI
/// it roots can answer, and asking would invite a self-signed CRL to speak for
/// itself.
pub fn check_path(input: &PathRevocationInput<'_>) -> PathRevocation {
    check_path_at(input, crate::certs::AnchorStatus::none())
}

/// [`check_path`], told what the caller knows about each anchor.
///
/// `status` reaches only the RFC 6960 section 2.2 trusted-responder model: a
/// responder whose own path ends at a trusted-list service that was not
/// granted at the response's `producedAt` authorises nothing, exactly as that
/// anchor would not have ended any other path.
pub fn check_path_at(
    input: &PathRevocationInput<'_>,
    status: crate::certs::AnchorStatus<'_>,
) -> PathRevocation {
    let PathRevocationInput {
        path,
        candidates,
        anchors,
        data,
        time,
        // `summarise` reads it from the input; destructuring it here would
        // only shadow that.
        time_is_proven: _,
        policy,
        role,
        limits,
    } = *input;
    if policy == RevocationPolicy::NotChecked {
        return PathRevocation {
            per_certificate: path
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    if index + 1 == path.len() {
                        CertificateRevocation::trust_anchor()
                    } else {
                        CertificateRevocation::not_checked()
                    }
                })
                .collect(),
            check: Check::skipped(
                CheckCode::RevocationNotChecked,
                format!(
                    "revocation checking was switched off by the caller, so no signature can be reported as valid ({})",
                    role.as_str()
                ),
            ),
            notes: Vec::new(),
        };
    }
    if path.len() < 2 {
        // A path that never reached an anchor has nothing to check against.
        return PathRevocation {
            per_certificate: path
                .iter()
                .map(|_| {
                    CertificateRevocation::plain(
                        RevocationStatus::Unknown,
                        CheckCode::RevocationStatusUnknown,
                    )
                })
                .collect(),
            check: Check::unknown(
                CheckCode::RevocationStatusUnknown,
                format!(
                    "no validated certification path was available, so revocation could not be checked for {}{}",
                    role.as_str(),
                    unfetched(policy)
                ),
            ),
            notes: Vec::new(),
        };
    }

    let mut per_certificate = Vec::with_capacity(path.len());
    let mut disagreements: Vec<String> = Vec::new();
    for window in path.windows(2) {
        let answer = check_certificate(
            &window[0], &window[1], candidates, anchors, status, data, time, limits,
        );
        if let Some(sentence) = answer.disagreement {
            disagreements.push(sentence);
        }
        per_certificate.push(answer.entry);
    }
    per_certificate.push(CertificateRevocation::trust_anchor());

    let check = summarise(path, &per_certificate, input);
    let trusted = per_certificate
        .iter()
        .filter(|entry| entry.responder_model == Some(ResponderModel::Trusted))
        .count();
    let mut notes = Vec::new();
    if trusted > 0 {
        notes.push(Check::info(
            CheckCode::OcspResponderTrusted,
            format!(
                "in {}, {trusted} certificate(s) were answered for by an OCSP responder the issuing CA did not delegate to, accepted under RFC 6960 section 2.2 because its certificate carries id-kp-OCSPSigning and chains to a configured trust anchor",
                input.role.as_str()
            ),
        ));
    }
    if let Some(first) = disagreements.first() {
        notes.push(Check::info(
            CheckCode::RevocationSourcesDisagree,
            format!(
                "in {}, {} certificate(s) were answered for differently by different sources; {first}",
                input.role.as_str(),
                disagreements.len()
            ),
        ));
    }
    PathRevocation {
        per_certificate,
        check,
        notes,
    }
}

fn generalized(time: &der::asn1::GeneralizedTime) -> UnixTime {
    time.to_unix_duration().as_secs() as UnixTime
}

/// Whether data with this validity window may be believed at `time`.
///
/// There is no grace period. Data whose `nextUpdate` has passed is expired,
/// and a verifier that accepts expired revocation data has silently decided
/// how long it is willing to be wrong for.
fn covers(this_update: UnixTime, next_update: Option<UnixTime>, time: UnixTime) -> bool {
    match next_update {
        Some(next) => next > time,
        // With no `nextUpdate` the publisher promised nothing about how long
        // the answer holds, so it is only good for the instant it was made and
        // anything after it.
        None => this_update >= time,
    }
}

/// The certificate extension accessors this module needs, kept here so that
/// `certs.rs` stays about path validation.
impl ParsedCertificate {
    /// Whether this certificate may sign a CRL: RFC 5280 permits an absent
    /// `keyUsage`, and requires `cRLSign` in a present one.
    pub(crate) fn asserts_crl_sign(&self) -> bool {
        match self.key_usage() {
            Ok(Some(usage)) => usage.crl_sign(),
            Ok(None) => true,
            Err(()) => false,
        }
    }

    pub(crate) fn has_ocsp_signing_eku(&self) -> bool {
        self.extended_key_usages()
            .ok()
            .flatten()
            .is_some_and(|usages| usages.contains(&OID_KP_OCSP_SIGNING))
    }

    pub(crate) fn is_valid_at(&self, time: UnixTime) -> bool {
        let validity = &self.certificate.tbs_certificate.validity;
        time >= crate::certs::unix_time(validity.not_before)
            && time <= crate::certs::unix_time(validity.not_after)
    }

    pub(crate) fn crl_distribution_points(
        &self,
    ) -> Option<Vec<x509_cert::ext::pkix::crl::dp::DistributionPoint>> {
        let extensions = self.certificate.tbs_certificate.extensions.as_ref()?;
        let extension = extensions
            .iter()
            .find(|extension| extension.extn_id == OID_CRL_DISTRIBUTION_POINTS)?;
        Vec::<x509_cert::ext::pkix::crl::dp::DistributionPoint>::from_der(
            extension.extn_value.as_bytes(),
        )
        .ok()
    }
}

/// What a file in a revocation store turned out to hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationItemKind {
    Crl,
    Ocsp,
}

/// Classify one revocation-store file, accepting DER or PEM.
///
/// **Every entry is parsed here**, so a store that loads is a store whose every
/// byte was understood: a half-loaded revocation store would silently change
/// what "no revocation data" means, and "no data" is a verdict-affecting
/// answer. The error names no path, because the path may be private.
pub fn classify(bytes: &[u8]) -> Result<(RevocationItemKind, Vec<u8>), String> {
    let der = match std::str::from_utf8(bytes) {
        Ok(text) if text.contains("-----BEGIN") => {
            let (label, der) = pem_rfc7468::decode_vec(text.trim().as_bytes())
                .map_err(|_| "a revocation store file is malformed PEM".to_owned())?;
            match label {
                "X509 CRL" | "CRL" => {
                    return CertificateList::from_der(&der)
                        .map(|_| (RevocationItemKind::Crl, der.clone()))
                        .map_err(|_| "a revocation store PEM block is not a valid CRL".to_owned());
                }
                "OCSP RESPONSE" => der,
                _ => {
                    return Err(
                        "a revocation store file is PEM but not a CRL or an OCSP response"
                            .to_owned(),
                    );
                }
            }
        }
        _ => bytes.to_vec(),
    };
    if CertificateList::from_der(&der).is_ok() {
        return Ok((RevocationItemKind::Crl, der));
    }
    if OcspResponse::from_der(&der).is_ok() || BasicOcspResponse::from_der(&der).is_ok() {
        return Ok((RevocationItemKind::Ocsp, der));
    }
    Err("a revocation store file is neither a CRL nor an OCSP response".to_owned())
}

/// Stage E: ask the revocation material about every certificate in the
/// signer's chain, and attach the answers to the reported chain.
///
/// `time_is_proven` says whether the validation time came from a fully
/// verified signature timestamp rather than from `--at` or the clock. Only a
/// timestamp *proves* it, and that difference decides whether a revocation
/// dated after it may be dismissed.
pub(crate) fn check_signer_chain(
    context: &crate::Context<'_, '_, '_, '_>,
    signer_path: crate::certs::SignerPath,
    data: &RevocationData<'_>,
    signature_time: UnixTime,
    time_is_proven: bool,
    report: &mut crate::report::SignatureReport,
) {
    let mut chain = signer_path.chain;
    if signer_path.path.is_empty() {
        // No validated path means no issuer to check anything against.
        report.checks.push(match context.revocation_policy {
            RevocationPolicy::NotChecked => Check::skipped(
                CheckCode::RevocationNotChecked,
                "revocation checking was switched off by the caller",
            ),
            policy @ (RevocationPolicy::Offline
            | RevocationPolicy::Online
            | RevocationPolicy::OnlineNoAnchors) => Check::unknown(
                CheckCode::RevocationStatusUnknown,
                format!(
                    "no validated certification path was available, so revocation could not be checked{}",
                    unfetched(policy)
                ),
            ),
        });
    } else {
        let outcome = check_path_at(
            &PathRevocationInput {
                anchors: &context.anchors,
                path: &signer_path.path,
                candidates: &signer_path.candidates,
                data,
                time: signature_time,
                time_is_proven,
                policy: context.revocation_policy,
                role: ChainRole::Signer,
                limits: &context.options.limits,
            },
            crate::certs::AnchorStatus::new(&context.anchor_provenance),
        );
        for (entry, status) in chain.iter_mut().zip(outcome.per_certificate) {
            entry.revocation = Some(status);
        }
        report.checks.push(outcome.check);
        report.checks.extend(outcome.notes);
    }
    report.chain = chain;
}
