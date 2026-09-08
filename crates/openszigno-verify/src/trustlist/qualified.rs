//! The qualified status of one validated chain.
//!
//! The determination is made over the whole chain rather than over its anchor,
//! and it can never grant trust: it says whether a chain some anchor already
//! validated is covered by a CA/QC service a trusted list records as granted
//! at the validation time.

use crate::certs::{CertificateSource, ParsedCertificate};
use crate::codes::{Check, CheckCode};
use crate::trust::{ServiceIdentity, TrustServiceIdentity, UnixTime};

use super::services::{EIDAS_APPLICATION_DATE, ServiceType};

/// What was concluded about one chain's qualified status.
pub(crate) struct Qualification {
    pub(crate) qualified: Option<bool>,
    pub(crate) device: Option<bool>,
    pub(crate) service: Option<String>,
    pub(crate) check: Check,
}

/// Whether one trusted-list service identity covers a validated chain.
///
/// The three identity forms are not equally strong, and the difference is
/// deliberate rather than incidental:
///
/// - **`X509Certificate`** is the only form that carries a key, so it is the
///   only one that can say "this certificate *was issued by* the listed
///   service" — a verified signature, not a name match. It is also the only
///   form that becomes a trust anchor.
/// - **`X509SKI`** names a certificate by the `subjectKeyIdentifier` a CA
///   chose to write into it. It can only recognise a certificate already in
///   the validated chain; it proves nothing on its own and cannot establish an
///   issuing relationship.
/// - **`X509SubjectName`** is weaker still: a name. It is compared through
///   [`crate::certs::name_key`] — every attribute type and value, in order,
///   exactly as written — because this project implements no RFC 4518 name
///   preparation and a lenient string comparison is exactly the sort of thing
///   that quietly widens trust.
///
/// Both weak forms are read only because a real national list uses them, and
/// they can only decide `qualified` — a legal category — over a chain some
/// anchor has already validated cryptographically. Neither can grant trust.
fn identity_covers(identity: &ServiceIdentity, path: &[ParsedCertificate]) -> Option<&'static str> {
    match identity {
        ServiceIdentity::Certificate(der) => {
            let listed = ParsedCertificate::from_der(der, CertificateSource::TrustList)?;
            path.iter()
                .any(|certificate| {
                    certificate.der == listed.der
                        || (certificate.issuer_der() == listed.subject_der()
                            && crate::certs::verify_issued_by(certificate, &listed))
                })
                .then_some("its X509Certificate identity")
        }
        ServiceIdentity::SubjectKeyIdentifier(ski) => path
            .iter()
            .any(|certificate| certificate.subject_key_identifier().as_ref() == Some(ski))
            .then_some("its X509SKI identity, which names a certificate without supplying one"),
        ServiceIdentity::SubjectName(key) => path
            .iter()
            .any(|certificate| certificate.subject_name_key() == *key)
            .then_some(
                "its X509SubjectName identity, matched attribute by attribute and weaker than a certificate identity",
            ),
    }
}

/// Decide the qualified status of one validated chain.
///
/// The determination is made over the **whole chain**, not over its anchor. In
/// a real trusted list the CA/QC service identities are the issuing CAs, which
/// are intermediates; the root above them is often present only in a
/// `--trust-store` directory, and sometimes is not listed at all. Asking only
/// the anchor therefore reports "not determined" for precisely the chains a
/// trusted list exists to describe.
///
/// So: a chain is qualified when some certificate in it **is**, or was
/// **issued by**, the service digital identity of a CA/QC service the list
/// records as granted at the validation time. "Issued by" is a verified
/// signature, not a name match, so nothing is gained by minting a certificate
/// that merely claims the right issuer. The `X509SKI` and `X509SubjectName`
/// identity forms recognise a chain certificate without being able to state an
/// issuing relationship; see [`identity_covers`].
///
/// The signer's own `QCStatements` may then contradict the list, and do when a
/// certificate issued after eIDAS applied carries the extension without
/// `QcCompliance`, or carries one that will not parse. A post-eIDAS
/// certificate with **no** `QCStatements` extension at all does not contradict
/// anything, and the determination rests on the trusted list alone, exactly as
/// it does for a pre-eIDAS certificate. That is the looser of the two readings
/// and it is deliberate: the trusted list is the authority on which CA may
/// issue qualified certificates, and an issuer that omitted an assertion has
/// not denied it.
///
/// The answer is `None`, never `false`, when no trusted list covers the chain:
/// "not determined" and "determined not to be qualified" are different
/// statements and the report keeps them apart.
pub(crate) fn qualification(
    services: &[TrustServiceIdentity],
    path: &[ParsedCertificate],
    time: UnixTime,
) -> Qualification {
    let mut matched: Option<(&TrustServiceIdentity, &'static str)> = None;
    for service in services {
        if !service.service.granted_at(time, ServiceType::CaQc) {
            continue;
        }
        if let Some(how) = identity_covers(&service.identity, path) {
            matched = Some((service, how));
            break;
        }
    }

    let Some((service, how)) = matched else {
        if services.is_empty() {
            return Qualification {
                qualified: None,
                device: None,
                service: None,
                check: Check::info(
                    CheckCode::CertificateQualifiedUnknown,
                    "no trusted list was consulted, so this chain's qualified status is not determined",
                ),
            };
        }
        return Qualification {
            qualified: Some(false),
            device: None,
            service: None,
            check: Check::info(
                CheckCode::CertificateNotQualified,
                "no certificate in the validated chain is, or was issued by, a trusted-list CA/QC service granted at the validation time",
            ),
        };
    };
    let record = &service.service;
    let service_name = record.service_name.clone();
    let named = service_name
        .as_deref()
        .map(|name| format!(" ({name})"))
        .unwrap_or_default();
    // Which status was honoured is part of the finding: an eIDAS `granted` and
    // a pre-eIDAS `accredited` or `undersupervision` are different statements,
    // and the second is honoured only for the historical window before eIDAS
    // applied.
    let status = record
        .status_name_at(time)
        .map(|status| format!(", recorded as {status} at the validation time"))
        .unwrap_or_default();

    let leaf = &path[0];
    let post_eidas = crate::certs::unix_time(leaf.certificate.tbs_certificate.validity.not_before)
        >= EIDAS_APPLICATION_DATE;
    let (contradicts, device) = match leaf.qc_statement_oids() {
        Ok(Some(oids)) => (
            !oids.contains(&crate::certs::OID_QC_COMPLIANCE),
            Some(oids.contains(&crate::certs::OID_QC_SSCD)),
        ),
        // No statement is not a denial; the list is the authority.
        Ok(None) => (false, None),
        // A malformed extension is not read past.
        Err(()) => (true, None),
    };
    if post_eidas && contradicts {
        return Qualification {
            qualified: Some(false),
            device,
            service: service_name,
            check: Check::info(
                CheckCode::CertificateNotQualified,
                format!(
                    "a trusted-list CA/QC service{named} covers this chain, but the signing certificate was issued after eIDAS applied and its QCStatements do not assert QcCompliance"
                ),
            ),
        };
    }
    Qualification {
        qualified: Some(true),
        device,
        service: service_name,
        check: Check::info(
            CheckCode::CertificateQualified,
            format!(
                "the validated chain is covered by a trusted-list CA/QC service{named} granted at the validation time through {how}{status}"
            ),
        ),
    }
}
