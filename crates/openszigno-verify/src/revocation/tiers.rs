//! Source priority, coverage, fallback, and the sentences a path's answers
//! are folded into.
//!
//! The tier order is deliberate: a signature's own `RevocationValues` were
//! collected when the signature was made and are what an archived,
//! network-free validation is meant to rely on; the store is the operator's
//! material and comes second; online material comes last, because it can only
//! fill a gap the caller's own material left.

use serde::Serialize;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

use crate::certs::ParsedCertificate;
use crate::codes::{Check, CheckCode};
use crate::policy::{MAX_REVOCATION_ITEM_BYTES, VerifyLimits};
use crate::trust::{RevocationPolicy, UnixTime, format_rfc3339};

use super::crl::crl_answer;
use super::ocsp::{ResponderModel, ocsp_answer};
use super::{CertificateRevocation, PathRevocationInput, RevocationData, RevocationStatus};

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
pub(super) fn summarise(
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
            let source = match input.policy {
                RevocationPolicy::Online => {
                    &format!("{source}, and nothing usable was fetched online either")
                }
                // The gap is the *reason* nothing was fetched, so it is named
                // here rather than left to the policy check alone: a reader of
                // this sentence is the one who has to act on it.
                RevocationPolicy::OnlineNoAnchors => &format!(
                    "{source}, and --online fetched nothing because no trust anchors are configured, so no certificate sits on a path to one"
                ),
                RevocationPolicy::NotChecked | RevocationPolicy::Offline => source,
            };
            format!(
                "in {chain}, no usable revocation data covers {what}: {source}{}",
                crl_hint(&path[index])
            )
        }
    }
}

/// The outcome of consulting one CRL or one OCSP response.
pub(super) enum Answer {
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
pub(super) fn check_certificate(
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
    let mut refused: Option<(RevocationOrigin, String)> = None;
    for (origin, items) in tiers {
        for item in items.iter().take(limits.max_revocation_items) {
            // Oversized evidence is refused *and named*. Skipping it silently
            // is what made a large CRL load, sit in the store, and answer
            // nothing.
            if item.len() > MAX_REVOCATION_ITEM_BYTES {
                let reason = format!(
                    "it is {} bytes, over the {MAX_REVOCATION_ITEM_BYTES}-byte limit on one CRL or OCSP response",
                    item.len()
                );
                record_refusal(&mut refused, &mut fallback, origin, reason);
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
                    record_refusal(&mut refused, &mut fallback, origin, reason.to_owned());
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
                    entry.detail = superseded(refused.as_ref(), origin);
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
                    entry.detail = superseded(refused.as_ref(), origin);
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

/// Remember one refused source: the first refusal is what the report names,
/// and it stays visible whether or not a later tier answered.
fn record_refusal(
    refused: &mut Option<(RevocationOrigin, String)>,
    fallback: &mut Option<CertificateRevocation>,
    origin: RevocationOrigin,
    reason: String,
) {
    if refused.is_none() {
        *refused = Some((origin, reason.clone()));
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

/// The sentence recording that something was refused before `used` answered.
fn superseded(
    refused: Option<&(RevocationOrigin, String)>,
    used: RevocationOrigin,
) -> Option<String> {
    let (origin, reason) = refused?;
    Some(format!(
        "{} was refused because {reason}; {} was used instead",
        origin.describe(),
        used.describe()
    ))
}
