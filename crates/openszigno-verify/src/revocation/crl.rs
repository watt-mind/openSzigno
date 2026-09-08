//! CRL validation and lookup, RFC 5280 section 6.3.
//!
//! Every restriction this build cannot evaluate makes a CRL unusable rather
//! than partly understood, so a partial CRL is never mistaken for a complete
//! one: a delta CRL, an indirect CRL, a partitioned CRL naming a distribution
//! point the certificate does not, and a scope restricted to reasons or to
//! attribute certificates are all refused, as is any other critical extension.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::crl::{CertificateList, RevokedCert};
use x509_cert::ext::pkix::CrlReason;
use x509_cert::ext::pkix::crl::IssuingDistributionPoint;
use x509_cert::ext::pkix::name::DistributionPointName;

use crate::certs::{ParsedCertificate, verify_der_signature};
use crate::trust::UnixTime;

use super::covers;
use super::tiers::Answer;

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

/// The critical CRL extensions this module implements. Every other critical
/// extension makes the CRL unusable rather than partly understood.
const IMPLEMENTED_CRITICAL_CRL: &[ObjectIdentifier] = &[OID_ISSUING_DISTRIBUTION_POINT];

/// The CRL entry extensions this module understands.
const IMPLEMENTED_ENTRY: &[ObjectIdentifier] = &[OID_CRL_REASON, OID_INVALIDITY_DATE];

pub(super) fn crl_answer(
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

pub(super) const fn reason_name(reason: CrlReason) -> &'static str {
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
