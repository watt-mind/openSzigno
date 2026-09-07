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
const OID_KP_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

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
}

impl RevocationOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmbeddedCrl => "embedded_crl",
            Self::EmbeddedOcsp => "embedded_ocsp",
            Self::StoreCrl => "store_crl",
            Self::StoreOcsp => "store_ocsp",
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
}

impl RevocationData<'_> {
    fn is_empty(&self) -> bool {
        self.embedded_crls.is_empty()
            && self.embedded_ocsp.is_empty()
            && self.store_crls.is_empty()
            && self.store_ocsp.is_empty()
    }
}

/// The revocation outcome for a whole path.
pub struct PathRevocation {
    /// One entry per certificate in the path, in the same order.
    pub per_certificate: Vec<CertificateRevocation>,
    /// The single check the path contributes to the signature's verdict.
    pub check: Check,
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
    }
}

/// Check every certificate in `path` except the trust anchor.
///
/// `path[0]` is the end-entity certificate and the last element is the anchor.
/// The anchor is skipped on purpose: its revocation is not something the PKI
/// it roots can answer, and asking would invite a self-signed CRL to speak for
/// itself.
pub fn check_path(
    path: &[ParsedCertificate],
    candidates: &[ParsedCertificate],
    data: &RevocationData<'_>,
    time: UnixTime,
    policy: RevocationPolicy,
    limits: &VerifyLimits,
) -> PathRevocation {
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
                "revocation checking was switched off by the caller, so no signature can be reported as valid",
            ),
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
                "no validated certification path was available, so revocation could not be checked",
            ),
        };
    }

    let mut per_certificate = Vec::with_capacity(path.len());
    for window in path.windows(2) {
        per_certificate.push(check_certificate(
            &window[0], &window[1], candidates, data, time, limits,
        ));
    }
    per_certificate.push(CertificateRevocation::trust_anchor());

    let check = summarise(path, &per_certificate, data);
    PathRevocation {
        per_certificate,
        check,
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
fn summarise(
    path: &[ParsedCertificate],
    entries: &[CertificateRevocation],
    data: &RevocationData<'_>,
) -> Check {
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
                "{} was revoked at {when} ({}), at or before the validation time",
                describe(path, index),
                entry.reason.unwrap_or("no reason given")
            ),
        );
    }
    // The worst remaining answer decides, and its own code is kept so the
    // caller learns *why* the tool could not conclude.
    for code in [
        CheckCode::CertRevokedAfterValidationTime,
        CheckCode::RevocationDataInvalid,
        CheckCode::RevocationDataStale,
        CheckCode::RevocationStatusUnknown,
    ] {
        if let Some((index, _)) = entries
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.code == code.as_str())
        {
            return Check::unknown(code, message_for(code, path, index, data));
        }
    }
    Check::passed(
        CheckCode::RevocationOk,
        format!(
            "fresh, verified revocation data covers all {checked} non-anchor certificates in the path"
        ),
    )
}

fn message_for(
    code: CheckCode,
    path: &[ParsedCertificate],
    index: usize,
    data: &RevocationData<'_>,
) -> String {
    let what = describe(path, index);
    match code {
        CheckCode::CertRevokedAfterValidationTime => format!(
            "{what} was revoked after the validation time; that revocation does not apply at the instant being validated, and the tool declines to call the result good"
        ),
        CheckCode::RevocationDataInvalid => format!(
            "the revocation data for {what} could not be used: it was not signed by an authorised issuer, or it uses a form this build refuses"
        ),
        CheckCode::RevocationDataStale => format!(
            "the revocation data for {what} had expired before the validation time{}",
            crl_hint(&path[index])
        ),
        _ => {
            let source = if data.is_empty() {
                "the signature embeds none and no --revocation-store was given"
            } else {
                "neither the signature's own RevocationValues nor the revocation store covers it"
            };
            format!(
                "no usable revocation data covers {what}: {source}{}",
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
    },
    Revoked {
        time: UnixTime,
        reason: Option<&'static str>,
        this_update: UnixTime,
        next_update: Option<UnixTime>,
        produced_at: Option<UnixTime>,
    },
    /// The data is well formed and authorised but says nothing about this
    /// certificate, or has expired.
    Stale,
    /// The data could not be used at all.
    Invalid,
    /// The data is about some other certificate; not a finding.
    NotApplicable,
}

/// Consult every source, in priority order, for one certificate.
fn check_certificate(
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    data: &RevocationData<'_>,
    time: UnixTime,
    limits: &VerifyLimits,
) -> CertificateRevocation {
    // The order is deliberate. A signature's own `RevocationValues` were
    // collected when the signature was made and are what an archived,
    // network-free validation is meant to rely on; the store is the operator's
    // material and comes second. Within each tier OCSP is asked first, because
    // it answers about this certificate rather than about a list.
    let tiers: [(RevocationOrigin, &[Vec<u8>]); 4] = [
        (RevocationOrigin::EmbeddedOcsp, data.embedded_ocsp),
        (RevocationOrigin::EmbeddedCrl, data.embedded_crls),
        (RevocationOrigin::StoreOcsp, data.store_ocsp),
        (RevocationOrigin::StoreCrl, data.store_crls),
    ];

    let mut fallback: Option<CertificateRevocation> = None;
    for (origin, items) in tiers {
        for item in items.iter().take(limits.max_revocation_items) {
            if item.len() > MAX_ITEM_BYTES {
                continue;
            }
            let answer = match origin {
                RevocationOrigin::EmbeddedOcsp | RevocationOrigin::StoreOcsp => {
                    ocsp_answer(item, subject, issuer, time)
                }
                RevocationOrigin::EmbeddedCrl | RevocationOrigin::StoreCrl => {
                    crl_answer(item, subject, issuer, candidates, time)
                }
            };
            match answer {
                Answer::NotApplicable => continue,
                Answer::Invalid => {
                    fallback.get_or_insert_with(|| {
                        let mut entry = CertificateRevocation::plain(
                            RevocationStatus::Unknown,
                            CheckCode::RevocationDataInvalid,
                        );
                        entry.source = Some(origin);
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
                } => {
                    let mut entry = CertificateRevocation::plain(
                        RevocationStatus::Good,
                        CheckCode::RevocationOk,
                    );
                    entry.source = Some(origin);
                    entry.this_update = Some(format_rfc3339(this_update));
                    entry.next_update = next_update.map(format_rfc3339);
                    entry.produced_at = produced_at.map(format_rfc3339);
                    return entry;
                }
                Answer::Revoked {
                    time: revoked_at,
                    reason,
                    this_update,
                    next_update,
                    produced_at,
                } => {
                    let (status, code) = if revoked_at <= time {
                        (RevocationStatus::Revoked, CheckCode::CertRevoked)
                    } else {
                        (
                            RevocationStatus::Unknown,
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
        return Answer::Invalid;
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
                return Answer::Invalid;
            }
            if extension.critical && !IMPLEMENTED_CRITICAL_CRL.contains(&extension.extn_id) {
                return Answer::Invalid;
            }
            if extension.extn_id == OID_ISSUING_DISTRIBUTION_POINT {
                let Ok(point) = IssuingDistributionPoint::from_der(extension.extn_value.as_bytes())
                else {
                    return Answer::Invalid;
                };
                if !idp_covers(&point, subject) {
                    return Answer::Invalid;
                }
            }
        }
    }

    // The signature, by the CA itself or by a delegate it authorised.
    if !crl_signature_verifies(&crl, issuer, candidates, time) {
        return Answer::Invalid;
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
                return Answer::Invalid;
            }
            if extension.critical && !IMPLEMENTED_ENTRY.contains(&extension.extn_id) {
                return Answer::Invalid;
            }
            if extension.extn_id == OID_CRL_REASON {
                let Ok(code) = CrlReason::from_der(extension.extn_value.as_bytes()) else {
                    return Answer::Invalid;
                };
                if code == CrlReason::RemoveFromCRL {
                    // `removeFromCRL` only means anything in a delta CRL, and
                    // delta CRLs are refused, so this entry is incoherent.
                    return Answer::Invalid;
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

fn ocsp_answer(
    der: &[u8],
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
    time: UnixTime,
) -> Answer {
    // An `EncapsulatedOCSPValue` holds a whole `OCSPResponse`; a store file may
    // hold either that or a bare `BasicOCSPResponse`.
    let basic = match OcspResponse::from_der(der) {
        Ok(response) => {
            if response.response_status != OcspResponseStatus::Successful {
                // A responder that reported a failure carries no status to
                // believe; reading past it would turn a refusal into an answer.
                return Answer::Invalid;
            }
            let Some(bytes) = response.response_bytes else {
                return Answer::Invalid;
            };
            if bytes.response_type != const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC {
                return Answer::Invalid;
            }
            match BasicOcspResponse::from_der(bytes.response.as_bytes()) {
                Ok(basic) => basic,
                Err(_) => return Answer::Invalid,
            }
        }
        Err(_) => match BasicOcspResponse::from_der(der) {
            Ok(basic) => basic,
            Err(_) => return Answer::Invalid,
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

    if !responder_authorised(&basic, issuer, time) {
        return Answer::Invalid;
    }

    let produced_at = generalized(&basic.tbs_response_data.produced_at.0);
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
        },
        CertStatus::Unknown(_) => Answer::Stale,
        CertStatus::Revoked(info) => Answer::Revoked {
            time: generalized(&info.revocation_time.0),
            reason: info.revocation_reason.map(reason_name),
            this_update,
            next_update,
            produced_at: Some(produced_at),
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

/// RFC 6960 section 4.2.2.2: a response is authorised when the CA signed it
/// itself, or when a certificate the CA issued carries `id-kp-OCSPSigning`.
fn responder_authorised(
    basic: &BasicOcspResponse,
    issuer: &ParsedCertificate,
    time: UnixTime,
) -> bool {
    let Ok(message) = basic.tbs_response_data.to_der() else {
        return false;
    };
    let Some(signature) = basic.signature.as_bytes() else {
        return false;
    };
    let algorithm = basic.signature_algorithm.oid;

    if responder_names(&basic.tbs_response_data.responder_id, issuer)
        && verify_der_signature(&issuer.certificate, algorithm, &message, signature).is_ok()
    {
        return true;
    }

    let delegates = basic.certs.as_deref().unwrap_or_default();
    delegates.iter().any(|certificate| {
        let Ok(der) = certificate.to_der() else {
            return false;
        };
        let Some(parsed) =
            ParsedCertificate::from_der(&der, crate::certs::CertificateSource::OcspResponse)
        else {
            return false;
        };
        responder_names(&basic.tbs_response_data.responder_id, &parsed)
            && parsed.has_ocsp_signing_eku()
            && parsed.is_valid_at(time)
            && parsed.issuer_der() == issuer.subject_der()
            && crate::certs::verify_issued_by(&parsed, issuer)
            && verify_der_signature(&parsed.certificate, algorithm, &message, signature).is_ok()
    })
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
