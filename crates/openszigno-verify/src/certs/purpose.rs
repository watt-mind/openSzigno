//! The `extendedKeyUsage` policy a built path is validated under.
//!
//! The purpose selects which extended key usages a certificate in the path may
//! carry, and nothing else: every other rule in `check_path` applies
//! identically whatever the purpose is. The two checks below are the whole of
//! that policy, one for the end-entity certificate and one for the CAs above
//! it, plus the advisory a loosely filled `extendedKeyUsage` produces.

use const_oid::ObjectIdentifier;
use x509_cert::ext::pkix::KeyUsage;

use crate::codes::{Check, CheckCode};

use super::extensions::OID_EXT_KEY_USAGE;
use super::{ParsedCertificate, PathPurpose, malformed};

const OID_ANY_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");
/// `id-kp-timeStamping`, RFC 3161 section 2.3.
pub const OID_KP_TIME_STAMPING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
/// `id-kp-documentSigning`, RFC 9336. The purpose that exists precisely for
/// signing documents, rather than for authenticating a host or a mailbox.
/// `id-kp-OCSPSigning`, which RFC 6960 requires on a responder certificate
/// that is not the CA itself.
pub const OID_KP_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

pub const OID_KP_DOCUMENT_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.36");
/// `szOID_KP_DOCUMENT_SIGNING`, Microsoft's "Document Signing" extended key
/// usage from its private arc (`1.3.6.1.4.1.311.10.3.12`). It predates RFC
/// 9336 by two decades and is what qualified-signature CAs actually put in
/// signing certificates, so it is accepted for the same purpose.
pub const OID_MS_DOCUMENT_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.3.12");

/// The end-entity certificate's extended key usage, which RFC 5280 section
/// 4.2.1.12 makes a restriction on what the key may be used for **whether or
/// not the extension is marked critical**. An absent extension imposes no
/// restriction and is accepted; a present one must name a purpose that
/// covers this use:
///
/// - `anyExtendedKeyUsage`, which waives the restriction;
/// - `id-kp-documentSigning` (RFC 9336), the purpose that exists for exactly
///   this;
/// - `id-kp-timeStamping`, but only when the path is being validated for a
///   timestamp authority, where RFC 3161 additionally requires it to be the
///   *only* purpose and to be critical (checked on the token's own
///   certificate).
///
/// `id-kp-emailProtection` is not one of them: signing a message to a
/// mailbox is not signing a document. Neither are `serverAuth`,
/// `clientAuth`, `codeSigning` and `OCSPSigning`.
///
/// An EKU naming none of the accepted purposes is not automatically a
/// refusal, though. ETSI EN 319 412-2 makes `nonRepudiation`
/// (`contentCommitment`) *the* key-usage signal for a signing certificate,
/// and real qualified certificates pair it with an EKU that says
/// `emailProtection` and nothing else. Calling those signatures invalid
/// over a purpose field the issuer filled in loosely would be wrong. So:
/// with `nonRepudiation` asserted, an unrelated EKU downgrades to
/// `cert_key_usage_advisory` (`unknown`), which caps the verdict at
/// indeterminate and names what was found. Without `nonRepudiation` there
/// is no such signal, and the certificate is refused.
pub(super) fn check_end_entity_key_usage(
    path: &[&ParsedCertificate],
    purpose: PathPurpose,
    advisories: &mut Vec<Check>,
) -> Result<(), (CheckCode, String)> {
    if let Some(usages) = path[0].extended_key_usages().map_err(|()| malformed())? {
        let permitted = usages.contains(&OID_ANY_EXTENDED_KEY_USAGE)
            || match purpose {
                PathPurpose::Signing => {
                    usages.contains(&OID_KP_DOCUMENT_SIGNING)
                        || usages.contains(&OID_MS_DOCUMENT_SIGNING)
                }
                PathPurpose::TimeStamping => usages.contains(&OID_KP_TIME_STAMPING),
                PathPurpose::OcspSigning => usages.contains(&OID_KP_OCSP_SIGNING),
            };
        let non_repudiation = path[0]
            .extension::<KeyUsage>()
            .map_err(|()| malformed())?
            .is_some_and(|usage| usage.non_repudiation());
        if !permitted {
            if purpose == PathPurpose::Signing && non_repudiation {
                // Informational: ETSI EN 319 412-2 makes `nonRepudiation`
                // the signal, and a loosely filled EKU alongside it is a
                // reporting matter, not a determination the tool failed to
                // make.
                advisories.push(Check::info(
                    CheckCode::CertKeyUsageAdvisory,
                    format!(
                        "the signing certificate asserts nonRepudiation but its extendedKeyUsage names only: {}",
                        purpose_list(&usages)
                    ),
                ));
            } else {
                return Err((
                    CheckCode::CertKeyUsageInvalid,
                    "the end-entity certificate has an extendedKeyUsage that does not permit this use"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// A CA's extended key usage is only enforced when it is marked critical.
/// RFC 5280 gives no path-processing rule for EKU in a CA certificate, and
/// real eIDAS hierarchies carry advisory sets there; refusing them would
/// reject chains that are correct. A CA that marks the extension critical
/// has asked to be taken at its word, and is.
pub(super) fn check_ca_key_usage(
    path: &[&ParsedCertificate],
    purpose: PathPurpose,
) -> Result<(), (CheckCode, String)> {
    for certificate in path.iter().skip(1) {
        if !certificate.is_critical(OID_EXT_KEY_USAGE) {
            continue;
        }
        let usages = certificate
            .extended_key_usages()
            .map_err(|()| malformed())?
            .unwrap_or_default();
        let permitted = usages.contains(&OID_ANY_EXTENDED_KEY_USAGE)
            || match purpose {
                PathPurpose::Signing => usages.contains(&OID_KP_DOCUMENT_SIGNING),
                PathPurpose::TimeStamping => usages.contains(&OID_KP_TIME_STAMPING),
                PathPurpose::OcspSigning => usages.contains(&OID_KP_OCSP_SIGNING),
            };
        if !permitted {
            return Err((
                CheckCode::CertKeyUsageInvalid,
                "a CA in the path has a critical extendedKeyUsage that does not permit this use"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

/// The extended key usages found, as dotted OIDs.
///
/// Object identifiers are public constants, not signer data, so naming them is
/// what lets a caller see why a certificate was accepted only with a caveat.
/// The list is bounded, because the extension is attacker-controlled.
fn purpose_list(usages: &[ObjectIdentifier]) -> String {
    let mut names: Vec<String> = usages
        .iter()
        .take(8)
        .map(ObjectIdentifier::to_string)
        .collect();
    if usages.len() > names.len() {
        names.push("...".to_owned());
    }
    names.join(", ")
}
