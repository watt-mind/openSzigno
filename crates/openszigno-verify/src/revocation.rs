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
//!
//! # What is not checked
//!
//! The OCSP nonce is ignored, because offline validation replays a response
//! that was produced for someone else's request; a nonce could never match and
//! demanding one would make every archived response unusable. Freshness and
//! the `certID` binding carry the weight instead.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use x509_cert::crl::{CertificateList, RevokedCert};
use x509_cert::ext::pkix::CrlReason;
use x509_cert::ext::pkix::crl::IssuingDistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};

use crate::certs::{ParsedCertificate, verify_der_signature};
use crate::codes::{Check, CheckCode};
use crate::policy::VerifyLimits;
use crate::trust::{RevocationPolicy, UnixTime, format_rfc3339};

/// `id-ce-issuingDistributionPoint`.
///
/// Spelled out rather than taken from `IssuingDistributionPoint::OID`, because
/// `x509-cert` 0.2.5 associates that type with `id-pe-subjectInfoAccess` by
/// mistake, and trusting it would silently skip every scope check.
const OID_ISSUING_DISTRIBUTION_POINT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.28");
const OID_DELTA_CRL_INDICATOR: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.27");
const OID_CRL_REASON: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.21");
const OID_CERTIFICATE_ISSUER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.29");
const OID_INVALIDITY_DATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.24");
const OID_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
use crate::certs::OID_KP_OCSP_SIGNING;

const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// The critical CRL extensions this module implements. Every other critical
/// extension makes the CRL unusable rather than partly understood.
const IMPLEMENTED_CRITICAL_CRL: &[ObjectIdentifier] = &[OID_ISSUING_DISTRIBUTION_POINT];

/// The CRL entry extensions this module understands.
const IMPLEMENTED_ENTRY: &[ObjectIdentifier] = &[OID_CRL_REASON, OID_INVALIDITY_DATE];

/// The largest CRL or OCSP response this build will parse.
const MAX_ITEM_BYTES: usize = 8 * 1024 * 1024;

/// The largest number of CRL distribution point URLs repeated in a message.
const MAX_HINTED_URLS: usize = 2;

/// Where one certificate's revocation answer came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationOrigin {
    /// `xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue`.
    EmbeddedCrl,
    /// `xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue`.
    EmbeddedOcsp,
    /// A CRL file in `--revocation-store DIR`.
    StoreCrl,
    /// An OCSP response file in `--revocation-store DIR`.
    StoreOcsp,
    /// A CRL the CLI fetched from a distribution point the certificate
    /// publishes, under `--online`.
    OnlineCrl,
    /// An OCSP response the CLI fetched from an AIA responder the certificate
    /// publishes, under `--online`.
    OnlineOcsp,
}

impl RevocationOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmbeddedCrl => "embedded_crl",
            Self::EmbeddedOcsp => "embedded_ocsp",
            Self::StoreCrl => "store_crl",
            Self::StoreOcsp => "store_ocsp",
            Self::OnlineCrl => "online_crl",
            Self::OnlineOcsp => "online_ocsp",
        }
    }

    /// How to name this source in a sentence.
    const fn describe(self) -> &'static str {
        match self {
            Self::EmbeddedCrl => "a CRL the signature embeds",
            Self::EmbeddedOcsp => "an OCSP response the signature embeds",
            Self::StoreCrl => "a CRL from the revocation store",
            Self::StoreOcsp => "an OCSP response from the revocation store",
            Self::OnlineCrl => "a CRL fetched online",
            Self::OnlineOcsp => "an OCSP response fetched online",
        }
    }
}

/// Which RFC 6960 model authorised the responder that answered.
///
/// RFC 6960 section 2.2 gives a relying party three ways to accept an OCSP
/// response, and openSzigno implements all three with a fixed precedence:
///
/// 1. **`issuer`** — the CA that issued the queried certificate signed the
///    response itself. Nothing more is needed and nothing weaker is preferred.
/// 2. **`delegated`** — a certificate that CA issued, carrying
///    `id-kp-OCSPSigning`, signed it. The CA's own signature over that
///    certificate is the delegation.
/// 3. **`trusted`** — the responder is one the *relying party* trusts
///    directly: its certificate carries `id-kp-OCSPSigning` and its path
///    validates to a configured trust anchor at `producedAt`, even though the
///    queried certificate's issuer never delegated to it.
///
/// The third exists because central responders are real. A national CA
/// operator commonly runs one responder for every CA in its hierarchy, issued
/// by a sibling CA rather than by whichever CA issued the certificate being
/// asked about; a verifier that implemented only the first two models rejects
/// every one of those answers as unauthorised. Its authority is the caller's
/// trust store, which is why it comes last: it rests on what the operator
/// configured rather than on what the issuing CA said.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponderModel {
    Issuer,
    Delegated,
    Trusted,
}

impl ResponderModel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::Delegated => "delegated",
            Self::Trusted => "trusted",
        }
    }
}

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
    fn plain(status: RevocationStatus, code: CheckCode) -> Self {
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
    fn is_empty(&self) -> bool {
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
    const fn as_str(self) -> &'static str {
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
    /// rather than decide and so never block: currently
    /// `ocsp_responder_trusted`, emitted when a response was accepted under
    /// the RFC 6960 section 2.2 trusted-responder model, because that rests on
    /// the caller's own trust store rather than on the issuing CA's word and a
    /// reader is entitled to know which it was.
    pub notes: Vec<Check>,
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
            "revocation is checked from the signature's own RevocationValues and the revocation store first, and --online allowed CRL distribution points and AIA OCSP responders named by the certificates themselves to be fetched for what they did not cover; every fetched artefact was checked by the same offline rules",
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
    matches!(
        check_certificate(subject, issuer, candidates, anchors, data, time, limits).status,
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
                    "no validated certification path was available, so revocation could not be checked for {}",
                    role.as_str()
                ),
            ),
            notes: Vec::new(),
        };
    }

    let mut per_certificate = Vec::with_capacity(path.len());
    for window in path.windows(2) {
        per_certificate.push(check_certificate(
            &window[0], &window[1], candidates, anchors, data, time, limits,
        ));
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
    PathRevocation {
        per_certificate,
        check,
        notes,
    }
}

/// Name one certificate in a path the way a caller needs in order to act.
///
/// Only public CA material is used: a CA's subject common name and the issuer
/// common name of any certificate are names of organisations, which is what a
/// caller must know in order to fetch the right CRL. The **subject** of the
/// end-entity certificate is never named, because that is the signer.
fn describe(path: &[ParsedCertificate], index: usize) -> String {
    let certificate = &path[index];
    let issuer = crate::certs::common_name(&certificate.certificate.tbs_certificate.issuer);
    let issued_by = issuer
        .map(|name| format!(" issued by {name}"))
        .unwrap_or_default();
    if index == 0 {
        return format!("the end-entity certificate{issued_by}");
    }
    match crate::certs::common_name(&certificate.certificate.tbs_certificate.subject) {
        Some(subject) => format!("the intermediate CA {subject}{issued_by}"),
        None => format!("an intermediate CA{issued_by}"),
    }
}

/// The CRL distribution points a certificate publishes, as a hint a caller can
/// act on directly. These are URLs a CA publishes for exactly this purpose.
fn crl_hint(certificate: &ParsedCertificate) -> String {
    let Some(points) = certificate.crl_distribution_points() else {
        return String::new();
    };
    let mut urls: Vec<String> = Vec::new();
    for point in points {
        let Some(DistributionPointName::FullName(names)) = point.distribution_point.as_ref() else {
            continue;
        };
        for name in names {
            if let GeneralName::UniformResourceIdentifier(uri) = name {
                let url = crate::xades::sanitize(uri.as_str());
                if !url.is_empty() && !urls.contains(&url) {
                    urls.push(url);
                }
            }
        }
        if urls.len() >= MAX_HINTED_URLS {
            break;
        }
    }
    if urls.is_empty() {
        return String::new();
    }
    format!(
        "; it publishes its CRL at {}",
        urls[..urls.len().min(MAX_HINTED_URLS)].join(", ")
    )
}

/// Fold the per-certificate answers into the one check the verdict sees.
///
/// The message names **which** certificate is the problem, by role and by the
/// public CA names around it, and repeats the CRL distribution point that
/// certificate publishes when it has one. Without that, a caller reading "no
/// usable revocation data" cannot tell whether to fetch a CA's CRL or the
/// end-entity's, which is the difference between a fixable run and a dead end.
/// It also names *which chain* it is about, because a signature reports one of
/// these for its signer and one for each timestamp authority.
///
/// # Revocation after a proven validation time
///
/// ETSI EN 319 102-1 compares a revocation date against the best-signature-time.
/// When the validation time came from a **fully verified signature timestamp**,
/// that instant is proven: the signature demonstrably existed then, so a
/// revocation dated afterwards says the certificate was withdrawn later and
/// says nothing against the signature. That is reported as `info` and does not
/// block.
///
/// When the validation time is `--at` or the current clock it is *asserted*,
/// not proven — a caller can pass any `--at` they like — so the same finding
/// stays `unknown` and blocks. The difference between those two cases is the
/// whole reason a signature timestamp is worth having.
///
/// Either way it is never `passed`: the certificate really was revoked, and a
/// reader deserves to be told so.
fn summarise(
    path: &[ParsedCertificate],
    entries: &[CertificateRevocation],
    input: &PathRevocationInput<'_>,
) -> Check {
    let chain = input.role.as_str();
    let checked = entries
        .iter()
        .filter(|entry| entry.status != RevocationStatus::TrustAnchor)
        .count();
    if let Some((index, entry)) = entries
        .iter()
        .enumerate()
        .find(|(_, entry)| entry.status == RevocationStatus::Revoked)
    {
        let when = entry
            .revocation_time
            .as_deref()
            .unwrap_or("an unstated time");
        return Check::failed(
            CheckCode::CertRevoked,
            format!(
                "in {chain}, {} was revoked at {when} ({}), at or before the validation time",
                describe(path, index),
                entry.reason.unwrap_or("no reason given")
            ),
        );
    }
    // The worst remaining answer decides, and its own code is kept so the
    // caller learns *why* the tool could not conclude. A revocation after a
    // proven validation time is considered last, because it does not block and
    // must not mask a finding that does.
    for code in [
        CheckCode::RevocationDataInvalid,
        CheckCode::RevocationDataStale,
        CheckCode::RevocationStatusUnknown,
    ] {
        if let Some((index, entry)) = entries
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.code == code.as_str())
        {
            return Check::unknown(code, message_for(code, path, index, entry, input));
        }
    }
    if let Some((index, entry)) = entries
        .iter()
        .enumerate()
        .find(|(_, entry)| entry.status == RevocationStatus::RevokedAfterValidationTime)
    {
        let when = entry
            .revocation_time
            .as_deref()
            .unwrap_or("an unstated time");
        let reason = entry.reason.unwrap_or("no reason given");
        let what = describe(path, index);
        return if input.time_is_proven {
            Check::info(
                CheckCode::CertRevokedAfterValidationTime,
                format!(
                    "in {chain}, {what} was revoked at {when} ({reason}), after the validation time a verified timestamp proves; the revocation does not apply at the instant being validated"
                ),
            )
        } else {
            Check::unknown(
                CheckCode::CertRevokedAfterValidationTime,
                format!(
                    "in {chain}, {what} was revoked at {when} ({reason}), after the validation time — but that time is asserted rather than proven by a verified timestamp, so the tool declines to dismiss the revocation"
                ),
            )
        };
    }
    let note = entries
        .iter()
        .find_map(|entry| entry.detail.as_deref())
        .map(|detail| format!("; {detail}"))
        .unwrap_or_default();
    Check::passed(
        CheckCode::RevocationOk,
        format!(
            "in {chain}, fresh, verified revocation data covers all {checked} non-anchor certificates{note}"
        ),
    )
}

fn message_for(
    code: CheckCode,
    path: &[ParsedCertificate],
    index: usize,
    entry: &CertificateRevocation,
    input: &PathRevocationInput<'_>,
) -> String {
    let what = describe(path, index);
    let chain = input.role.as_str();
    match code {
        CheckCode::RevocationDataInvalid => match entry.detail.as_deref() {
            Some(detail) => {
                format!("in {chain}, the revocation data for {what} could not be used: {detail}")
            }
            None => format!(
                "in {chain}, the revocation data for {what} could not be used: it was not signed by an authorised issuer, or it uses a form this build refuses"
            ),
        },
        CheckCode::RevocationDataStale => format!(
            "in {chain}, the revocation data for {what} had expired before the validation time{}",
            crl_hint(&path[index])
        ),
        _ => {
            let source = if input.data.is_empty() {
                "the signature embeds none and no --revocation-store was given"
            } else {
                "neither the signature's own RevocationValues nor the revocation store covers it"
            };
            let source = if input.policy == RevocationPolicy::Online {
                &format!("{source}, and nothing usable was fetched online either")
            } else {
                source
            };
            format!(
                "in {chain}, no usable revocation data covers {what}: {source}{}",
                crl_hint(&path[index])
            )
        }
    }
}

/// The outcome of consulting one CRL or one OCSP response.
enum Answer {
    Good {
        this_update: UnixTime,
        next_update: Option<UnixTime>,
        produced_at: Option<UnixTime>,
        responder_model: Option<ResponderModel>,
    },
    Revoked {
        time: UnixTime,
        reason: Option<&'static str>,
        this_update: UnixTime,
        next_update: Option<UnixTime>,
        produced_at: Option<UnixTime>,
        responder_model: Option<ResponderModel>,
    },
    /// The data is well formed and authorised but says nothing about this
    /// certificate, or has expired.
    Stale,
    /// The data could not be used at all, and why. The reason is reported,
    /// because "unusable" without a cause is exactly the message an operator
    /// cannot act on.
    Invalid(&'static str),
    /// The data is about some other certificate; not a finding.
    NotApplicable,
}

/// Consult every source, in priority order, for one certificate.
fn check_certificate(
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    data: &RevocationData<'_>,
    time: UnixTime,
    limits: &VerifyLimits,
) -> CertificateRevocation {
    // The order is deliberate. A signature's own `RevocationValues` were
    // collected when the signature was made and are what an archived,
    // network-free validation is meant to rely on; the store is the operator's
    // material and comes second. Within each tier OCSP is asked first, because
    // it answers about this certificate rather than about a list.
    // Online material comes last: it can only fill a gap the caller's own
    // material left, never displace an answer that was already to hand.
    let tiers: [(RevocationOrigin, &[Vec<u8>]); 6] = [
        (RevocationOrigin::EmbeddedOcsp, data.embedded_ocsp),
        (RevocationOrigin::EmbeddedCrl, data.embedded_crls),
        (RevocationOrigin::StoreOcsp, data.store_ocsp),
        (RevocationOrigin::StoreCrl, data.store_crls),
        (RevocationOrigin::OnlineOcsp, data.online_ocsp),
        (RevocationOrigin::OnlineCrl, data.online_crls),
    ];

    let mut fallback: Option<CertificateRevocation> = None;
    // The first source that was consulted and refused. An unusable answer must
    // never end the search — a central responder this build cannot authorise
    // is a very ordinary thing to meet, and the CRL two tiers down answers the
    // same question — but it must stay visible, whether or not something later
    // rescued the certificate.
    let mut refused: Option<(RevocationOrigin, &'static str)> = None;
    for (origin, items) in tiers {
        for item in items.iter().take(limits.max_revocation_items) {
            if item.len() > MAX_ITEM_BYTES {
                continue;
            }
            let answer = match origin {
                RevocationOrigin::EmbeddedOcsp
                | RevocationOrigin::StoreOcsp
                | RevocationOrigin::OnlineOcsp => {
                    ocsp_answer(item, subject, issuer, candidates, anchors, time, limits)
                }
                RevocationOrigin::EmbeddedCrl
                | RevocationOrigin::StoreCrl
                | RevocationOrigin::OnlineCrl => {
                    crl_answer(item, subject, issuer, candidates, time)
                }
            };
            match answer {
                Answer::NotApplicable => continue,
                Answer::Invalid(reason) => {
                    if refused.is_none() {
                        refused = Some((origin, reason));
                    }
                    fallback.get_or_insert_with(|| {
                        let mut entry = CertificateRevocation::plain(
                            RevocationStatus::Unknown,
                            CheckCode::RevocationDataInvalid,
                        );
                        entry.source = Some(origin);
                        entry.detail = Some(format!(
                            "{} was refused because {reason}",
                            origin.describe()
                        ));
                        entry
                    });
                }
                Answer::Stale => {
                    let mut entry = CertificateRevocation::plain(
                        RevocationStatus::Unknown,
                        CheckCode::RevocationDataStale,
                    );
                    entry.source = Some(origin);
                    // Stale beats invalid as the reported reason: it names the
                    // fixable problem.
                    fallback = Some(entry);
                }
                Answer::Good {
                    this_update,
                    next_update,
                    produced_at,
                    responder_model,
                } => {
                    let mut entry = CertificateRevocation::plain(
                        RevocationStatus::Good,
                        CheckCode::RevocationOk,
                    );
                    entry.source = Some(origin);
                    entry.this_update = Some(format_rfc3339(this_update));
                    entry.next_update = next_update.map(format_rfc3339);
                    entry.produced_at = produced_at.map(format_rfc3339);
                    entry.responder_model = responder_model;
                    entry.detail = superseded(refused, origin);
                    return entry;
                }
                Answer::Revoked {
                    time: revoked_at,
                    reason,
                    this_update,
                    next_update,
                    produced_at,
                    responder_model,
                } => {
                    let (status, code) = if revoked_at <= time {
                        (RevocationStatus::Revoked, CheckCode::CertRevoked)
                    } else {
                        (
                            RevocationStatus::RevokedAfterValidationTime,
                            CheckCode::CertRevokedAfterValidationTime,
                        )
                    };
                    let mut entry = CertificateRevocation::plain(status, code);
                    entry.source = Some(origin);
                    entry.revocation_time = Some(format_rfc3339(revoked_at));
                    entry.reason = reason;
                    entry.this_update = Some(format_rfc3339(this_update));
                    entry.next_update = next_update.map(format_rfc3339);
                    entry.produced_at = produced_at.map(format_rfc3339);
                    entry.responder_model = responder_model;
                    entry.detail = superseded(refused, origin);
                    return entry;
                }
            }
        }
    }
    fallback.unwrap_or_else(|| {
        CertificateRevocation::plain(
            RevocationStatus::Unknown,
            CheckCode::RevocationStatusUnknown,
        )
    })
}

/// The sentence recording that something was refused before `used` answered.
fn superseded(
    refused: Option<(RevocationOrigin, &'static str)>,
    used: RevocationOrigin,
) -> Option<String> {
    let (origin, reason) = refused?;
    Some(format!(
        "{} was refused because {reason}; {} was used instead",
        origin.describe(),
        used.describe()
    ))
}

// ---------------------------------------------------------------------------
// CRLs, RFC 5280 section 6.3
// ---------------------------------------------------------------------------

fn crl_answer(
    der: &[u8],
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    time: UnixTime,
) -> Answer {
    let Ok(crl) = CertificateList::from_der(der) else {
        return Answer::Invalid("it is not a decodable CRL");
    };
    let tbs = &crl.tbs_cert_list;

    // Scope by issuer first: a CRL that does not belong to this certificate's
    // CA is simply about something else, not an error in this one.
    if tbs.issuer.to_der().unwrap_or_default() != subject.issuer_der() {
        return Answer::NotApplicable;
    }

    // Every critical extension must be one this build implements, and the
    // recognised ones must describe a scope that covers this certificate.
    if let Some(extensions) = tbs.crl_extensions.as_ref() {
        for extension in extensions.iter() {
            if extension.extn_id == OID_DELTA_CRL_INDICATOR {
                // A delta CRL is meaningless without the base it amends.
                return Answer::Invalid("it is a delta CRL and the base it amends is not to hand");
            }
            if extension.critical && !IMPLEMENTED_CRITICAL_CRL.contains(&extension.extn_id) {
                return Answer::Invalid(
                    "it marks an extension critical whose semantics this build does not implement",
                );
            }
            if extension.extn_id == OID_ISSUING_DISTRIBUTION_POINT {
                let Ok(point) = IssuingDistributionPoint::from_der(extension.extn_value.as_bytes())
                else {
                    return Answer::Invalid("its issuingDistributionPoint could not be decoded");
                };
                if !idp_covers(&point, subject) {
                    return Answer::Invalid(
                        "its issuingDistributionPoint describes a scope that does not cover this certificate",
                    );
                }
            }
        }
    }

    // The signature, by the CA itself or by a delegate it authorised.
    if !crl_signature_verifies(&crl, issuer, candidates, time) {
        return Answer::Invalid(
            "it was not signed by the issuing CA or by a delegate that CA authorised to sign CRLs",
        );
    }

    let this_update = crate::certs::unix_time(tbs.this_update);
    let next_update = tbs.next_update.map(crate::certs::unix_time);
    if !covers(this_update, next_update, time) {
        return Answer::Stale;
    }

    let serial = subject
        .certificate
        .tbs_certificate
        .serial_number
        .as_bytes()
        .to_vec();
    let entry = tbs.revoked_certificates.as_ref().and_then(|entries| {
        entries
            .iter()
            .find(|entry| entry.serial_number.as_bytes() == serial)
    });
    let Some(entry) = entry else {
        return Answer::Good {
            this_update,
            next_update,
            produced_at: None,
            responder_model: None,
        };
    };
    revoked_from_entry(entry, this_update, next_update)
}

fn revoked_from_entry(
    entry: &RevokedCert,
    this_update: UnixTime,
    next_update: Option<UnixTime>,
) -> Answer {
    let mut reason = None;
    if let Some(extensions) = entry.crl_entry_extensions.as_ref() {
        for extension in extensions.iter() {
            if extension.extn_id == OID_CERTIFICATE_ISSUER {
                // An entry that names a different certificate issuer is an
                // indirect-CRL entry, which this build refuses.
                return Answer::Invalid("one of its entries names a different certificate issuer");
            }
            if extension.critical && !IMPLEMENTED_ENTRY.contains(&extension.extn_id) {
                return Answer::Invalid(
                    "one of its entries marks an extension critical that this build does not implement",
                );
            }
            if extension.extn_id == OID_CRL_REASON {
                let Ok(code) = CrlReason::from_der(extension.extn_value.as_bytes()) else {
                    return Answer::Invalid(
                        "one of its entries carries an undecodable reason code",
                    );
                };
                if code == CrlReason::RemoveFromCRL {
                    // `removeFromCRL` only means anything in a delta CRL, and
                    // delta CRLs are refused, so this entry is incoherent.
                    return Answer::Invalid(
                        "one of its entries says removeFromCRL outside a delta CRL",
                    );
                }
                reason = Some(reason_name(code));
            }
        }
    }
    Answer::Revoked {
        time: crate::certs::unix_time(entry.revocation_date),
        reason,
        this_update,
        next_update,
        produced_at: None,
        responder_model: None,
    }
}

/// Whether a CRL's `issuingDistributionPoint` covers this certificate.
///
/// Fails closed: every restriction this build cannot evaluate makes the CRL
/// unusable, so a partial CRL is never mistaken for a complete one.
fn idp_covers(point: &IssuingDistributionPoint, subject: &ParsedCertificate) -> bool {
    if point.indirect_crl
        || point.only_contains_attribute_certs
        || point.only_some_reasons.is_some()
    {
        return false;
    }
    let is_ca = subject.is_certificate_authority();
    if point.only_contains_user_certs && is_ca {
        return false;
    }
    if point.only_contains_ca_certs && !is_ca {
        return false;
    }
    let Some(name) = point.distribution_point.as_ref() else {
        return true;
    };
    // A partitioned CRL is only about the certificates that point at it, so
    // the certificate must name the same distribution point.
    let DistributionPointName::FullName(names) = name else {
        // A name relative to the CRL issuer needs DN arithmetic this build
        // does not implement.
        return false;
    };
    let wanted: Vec<Vec<u8>> = names
        .iter()
        .filter_map(|general| general.to_der().ok())
        .collect();
    let Some(points) = subject.crl_distribution_points() else {
        return false;
    };
    points.iter().any(|point| {
        point.crl_issuer.is_none()
            && point.reasons.is_none()
            && match point.distribution_point.as_ref() {
                Some(DistributionPointName::FullName(names)) => names
                    .iter()
                    .filter_map(|general| general.to_der().ok())
                    .any(|encoded| wanted.contains(&encoded)),
                _ => false,
            }
    })
}

/// RFC 5280 section 6.3.3 step (f): the CRL must be signed by the CA that
/// issued the certificate, or by a certificate that CA issued which asserts
/// `cRLSign` and whose subject is the CRL issuer.
fn crl_signature_verifies(
    crl: &CertificateList,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    time: UnixTime,
) -> bool {
    let Ok(message) = crl.tbs_cert_list.to_der() else {
        return false;
    };
    let Some(signature) = crl.signature.as_bytes() else {
        return false;
    };
    let algorithm = crl.signature_algorithm.oid;

    let authorised = |certificate: &ParsedCertificate| -> bool {
        // Whoever signs a CRL must be entitled to: an absent keyUsage is
        // permitted by RFC 5280, a present one must assert cRLSign.
        certificate.asserts_crl_sign()
            && verify_der_signature(&certificate.certificate, algorithm, &message, signature)
                .is_ok()
    };

    if authorised(issuer) {
        return true;
    }
    let issuer_der = crl.tbs_cert_list.issuer.to_der().unwrap_or_default();
    candidates.iter().any(|candidate| {
        candidate.subject_der() == issuer_der
            && candidate.issuer_der() == issuer.subject_der()
            && candidate.is_valid_at(time)
            // The delegate must itself have been issued by the CA, or anyone
            // could mint a CRL signer with the right name.
            && crate::certs::verify_issued_by(candidate, issuer)
            && authorised(candidate)
    })
}

const fn reason_name(reason: CrlReason) -> &'static str {
    match reason {
        CrlReason::Unspecified => "unspecified",
        CrlReason::KeyCompromise => "key_compromise",
        CrlReason::CaCompromise => "ca_compromise",
        CrlReason::AffiliationChanged => "affiliation_changed",
        CrlReason::Superseded => "superseded",
        CrlReason::CessationOfOperation => "cessation_of_operation",
        CrlReason::CertificateHold => "certificate_hold",
        CrlReason::RemoveFromCRL => "remove_from_crl",
        CrlReason::PrivilegeWithdrawn => "privilege_withdrawn",
        CrlReason::AaCompromise => "aa_compromise",
    }
}

// ---------------------------------------------------------------------------
// OCSP, RFC 6960
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn ocsp_answer(
    der: &[u8],
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    time: UnixTime,
    limits: &VerifyLimits,
) -> Answer {
    // An `EncapsulatedOCSPValue` holds a whole `OCSPResponse`; a store file may
    // hold either that or a bare `BasicOCSPResponse`.
    let basic = match OcspResponse::from_der(der) {
        Ok(response) => {
            if response.response_status != OcspResponseStatus::Successful {
                // A responder that reported a failure carries no status to
                // believe; reading past it would turn a refusal into an answer.
                return Answer::Invalid("its OCSPResponseStatus is not successful");
            }
            let Some(bytes) = response.response_bytes else {
                return Answer::Invalid("it carries no response bytes");
            };
            if bytes.response_type != const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC {
                return Answer::Invalid("its response type is not id-pkix-ocsp-basic");
            }
            match BasicOcspResponse::from_der(bytes.response.as_bytes()) {
                Ok(basic) => basic,
                Err(_) => return Answer::Invalid("its BasicOCSPResponse could not be decoded"),
            }
        }
        Err(_) => match BasicOcspResponse::from_der(der) {
            Ok(basic) => basic,
            Err(_) => return Answer::Invalid("it is not a decodable OCSP response"),
        },
    };

    let Some(single) = basic
        .tbs_response_data
        .responses
        .iter()
        .find(|single| cert_id_matches(&single.cert_id, subject, issuer))
    else {
        return Answer::NotApplicable;
    };

    let produced_at = generalized(&basic.tbs_response_data.produced_at.0);
    let Some(responder_model) = responder_authorised(
        &basic,
        issuer,
        candidates,
        anchors,
        produced_at,
        time,
        limits,
    ) else {
        return Answer::Invalid(
            "the responder is not the issuing CA, is not a responder that CA delegated to, and does not chain to a configured trust anchor as a trusted responder",
        );
    };
    let responder_model = Some(responder_model);

    let this_update = generalized(&single.this_update.0);
    let next_update = single.next_update.as_ref().map(|time| generalized(&time.0));
    if !covers(this_update, next_update, time) {
        return Answer::Stale;
    }

    match &single.cert_status {
        CertStatus::Good(_) => Answer::Good {
            this_update,
            next_update,
            produced_at: Some(produced_at),
            responder_model,
        },
        CertStatus::Unknown(_) => Answer::Stale,
        CertStatus::Revoked(info) => Answer::Revoked {
            time: generalized(&info.revocation_time.0),
            reason: info.revocation_reason.map(reason_name),
            this_update,
            next_update,
            produced_at: Some(produced_at),
            responder_model,
        },
    }
}

/// RFC 6960 section 4.1.1: the `CertID` names the issuer by hashes of its DN
/// and public key, plus the certificate's serial number.
///
/// SHA-1 is accepted **here and only here**. These hashes identify which
/// certificate a response is about; they are not a signature, and RFC 6960
/// makes SHA-1 the default algorithm, so refusing it would make every real
/// OCSP response unusable while defending nothing. A second preimage would
/// only let an attacker point a response at a certificate whose issuer DN and
/// public key both collide, and the response's own signature still has to
/// verify under the pinned allowlist.
fn cert_id_matches(
    cert_id: &x509_ocsp::CertId,
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
) -> bool {
    if cert_id.serial_number.as_bytes()
        != subject.certificate.tbs_certificate.serial_number.as_bytes()
    {
        return false;
    }
    let Some(key) = issuer
        .certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
    else {
        return false;
    };
    let name = subject.issuer_der();
    let Some(name_hash) = digest_by_oid(cert_id.hash_algorithm.oid, &name) else {
        return false;
    };
    let Some(key_hash) = digest_by_oid(cert_id.hash_algorithm.oid, key) else {
        return false;
    };
    name_hash == cert_id.issuer_name_hash.as_bytes()
        && key_hash == cert_id.issuer_key_hash.as_bytes()
}

fn digest_by_oid(oid: ObjectIdentifier, bytes: &[u8]) -> Option<Vec<u8>> {
    match oid {
        OID_SHA1 => Some(Sha1::digest(bytes).to_vec()),
        OID_SHA256 => Some(Sha256::digest(bytes).to_vec()),
        OID_SHA384 => Some(Sha384::digest(bytes).to_vec()),
        OID_SHA512 => Some(Sha512::digest(bytes).to_vec()),
        _ => None,
    }
}

/// Which RFC 6960 model, if any, authorises this response.
///
/// Three models, tried in this order, and the order is the point:
///
/// 1. **Issuer.** The CA that issued the queried certificate signed the
///    response itself. It is the strongest answer available and nothing weaker
///    is looked at once it holds.
/// 2. **Delegated** (section 4.2.2.2). A certificate that same CA issued,
///    naming itself in the `ResponderID`, carrying `id-kp-OCSPSigning` and
///    valid at the time asked about, signed it. The CA's signature over the
///    responder certificate *is* the delegation, so this needs no trust store.
/// 3. **Trusted responder** (section 2.2). The responder is one the relying
///    party trusts directly: it carries `id-kp-OCSPSigning` and its path
///    validates to a configured trust anchor at `producedAt`, even though the
///    queried certificate's issuer never delegated to it.
///
/// The third model is not a relaxation of the first two, it is the third thing
/// RFC 6960 has always allowed, and real hierarchies need it: a national CA
/// operator commonly runs **one** responder for every CA it operates, issued
/// by a sibling CA rather than by whichever CA issued the certificate being
/// asked about. A verifier implementing only the delegation model rejects
/// every one of those answers as unauthorised, which is what openSzigno did
/// before M3 and is why 50 real responses came back
/// `revocation_data_invalid`.
///
/// What keeps it honest is where the authority comes from. A delegated
/// responder is vouched for by the issuing CA; a trusted responder is vouched
/// for by the **caller's own trust store or trusted list**, through a full
/// path validation with `id-kp-OCSPSigning` required on the leaf. A responder
/// that reaches no configured anchor authorises nothing, so this can never
/// admit a response the operator did not already choose to trust the signer
/// of. It is tried last so that a CA's own word always wins over the caller's
/// configuration where both are available.
fn responder_authorised(
    basic: &BasicOcspResponse,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    produced_at: UnixTime,
    time: UnixTime,
    limits: &VerifyLimits,
) -> Option<ResponderModel> {
    let Ok(message) = basic.tbs_response_data.to_der() else {
        return None;
    };
    let signature = basic.signature.as_bytes()?;
    let algorithm = basic.signature_algorithm.oid;
    let responder = &basic.tbs_response_data.responder_id;

    // 1. The issuing CA answered for itself.
    if responder_names(responder, issuer)
        && verify_der_signature(&issuer.certificate, algorithm, &message, signature).is_ok()
    {
        return Some(ResponderModel::Issuer);
    }

    // The certificates the response carries, plus everything else the run has
    // to hand. A central responder's own certificate usually travels with the
    // response; its issuing CA usually does not, and comes from the dossier's
    // `CertificateValues` or the trust store instead.
    let mut offered: Vec<ParsedCertificate> = Vec::new();
    for certificate in basic.certs.as_deref().unwrap_or_default() {
        if let Ok(der) = certificate.to_der()
            && let Some(parsed) =
                ParsedCertificate::from_der(&der, crate::certs::CertificateSource::OcspResponse)
        {
            offered.push(parsed);
        }
    }
    let named: Vec<&ParsedCertificate> = offered
        .iter()
        .chain(candidates.iter())
        .filter(|parsed| responder_names(responder, parsed))
        .collect();

    // 2. A responder the issuing CA delegated to.
    for parsed in &named {
        if parsed.has_ocsp_signing_eku()
            && parsed.is_valid_at(time)
            && parsed.issuer_der() == issuer.subject_der()
            && crate::certs::verify_issued_by(parsed, issuer)
            && verify_der_signature(&parsed.certificate, algorithm, &message, signature).is_ok()
        {
            return Some(ResponderModel::Delegated);
        }
    }

    // 3. A responder the caller trusts directly.
    //
    // The path is validated at `producedAt`, which is the instant the
    // responder asserts it made the statement: a responder certificate that
    // had expired by then was not entitled to say anything, and one that
    // expired afterwards said it while it still was. `keyUsage` is enforced by
    // the same path validator that enforces it everywhere else.
    if anchors.is_empty() {
        return None;
    }
    for parsed in &named {
        if !parsed.has_ocsp_signing_eku() {
            continue;
        }
        if verify_der_signature(&parsed.certificate, algorithm, &message, signature).is_err() {
            continue;
        }
        let pool: Vec<ParsedCertificate> = offered
            .iter()
            .chain(candidates.iter())
            .cloned()
            .collect::<Vec<_>>();
        let outcome = crate::certs::validate_path(
            parsed,
            &crate::certs::dedup(pool),
            anchors,
            produced_at,
            limits,
            crate::certs::PathPurpose::OcspSigning,
        );
        if outcome.code == CheckCode::CertPathOk {
            return Some(ResponderModel::Trusted);
        }
    }
    None
}

/// Whether a `ResponderID` names this certificate, by subject name or by the
/// SHA-1 hash of its public key that RFC 6960 prescribes.
fn responder_names(responder: &ResponderId, certificate: &ParsedCertificate) -> bool {
    match responder {
        ResponderId::ByName(name) => name.to_der().unwrap_or_default() == certificate.subject_der(),
        ResponderId::ByKey(hash) => certificate
            .certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .is_some_and(|key| Sha1::digest(key).to_vec() == hash.as_bytes()),
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

/// Build an RFC 6960 `OCSPRequest` asking about one certificate.
///
/// This is DER assembly, not networking: the crate still opens no socket, and
/// what the CLI does with the bytes is the CLI's business. Building the
/// request here keeps every line of OCSP ASN.1 this project speaks in one
/// file, next to the code that will have to make sense of the answer.
///
/// The `certID` is computed with **SHA-256**, which is inside the pinned
/// allowlist. RFC 6960 makes SHA-1 the default and a responder is entitled to
/// answer only about the `certID` it was asked about, so a responder that
/// insists on SHA-1 simply yields no usable answer and the certificate stays
/// `revocation_status_unknown` — the same place it was before anything was
/// fetched. Asking with SHA-1 to raise the hit rate would mean this build
/// *generating* a legacy digest, which is a different thing from accepting one
/// in an archived response it did not create.
///
/// No nonce is sent. A nonce defends a live request against replay, and the
/// response is going to be handed to a verifier that deliberately ignores
/// nonces because it must also read responses archived years ago; adding one
/// would defend nothing and would make some responders refuse outright.
pub fn ocsp_request(subject: &ParsedCertificate, issuer: &ParsedCertificate) -> Option<Vec<u8>> {
    use der::asn1::OctetString;

    let key = issuer
        .certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()?;
    let cert_id = x509_ocsp::CertId {
        hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: OID_SHA256,
            parameters: Some(der::Any::null()),
        },
        issuer_name_hash: OctetString::new(Sha256::digest(subject.issuer_der()).to_vec()).ok()?,
        issuer_key_hash: OctetString::new(Sha256::digest(key).to_vec()).ok()?,
        serial_number: subject.certificate.tbs_certificate.serial_number.clone(),
    };
    let request = x509_ocsp::OcspRequest {
        tbs_request: x509_ocsp::TbsRequest {
            version: x509_ocsp::Version::V1,
            requestor_name: None,
            request_list: vec![x509_ocsp::Request {
                req_cert: cert_id,
                single_request_extensions: None,
            }],
            request_extensions: None,
        },
        optional_signature: None,
    };
    request.to_der().ok()
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
