//! Extension decoding for a parsed certificate.
//!
//! Every reader here distinguishes "the extension is absent" from "the
//! extension is present but malformed": treating a decoding failure as absence
//! would make a corrupt `keyUsage`, `nameConstraints` or `QCStatements`
//! silently vanish, which is the wrong direction for every one of them.

use const_oid::AssociatedOid;
use const_oid::ObjectIdentifier;
use der::Decode;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, NameConstraints, SubjectAltName};

use super::ParsedCertificate;

pub(super) const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
/// `id-ad-ocsp`, the access method that names an OCSP responder.
const OID_AD_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
/// `id-pe-qcStatements`, RFC 3739 section 3.2.6.
const OID_QC_STATEMENTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.3");
/// `id-etsi-qcs-QcCompliance`, ETSI EN 319 412-5 section 4.2.1.
pub const OID_QC_COMPLIANCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.1");
/// `id-etsi-qcs-QcSSCD`, ETSI EN 319 412-5 section 4.2.2 (QSCD since eIDAS).
pub const OID_QC_SSCD: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.4");
/// The largest number of QCStatements this build will read from one
/// certificate before treating the extension as hostile.
const MAX_QC_STATEMENTS: usize = 64;

/// One `QCStatement`, RFC 3739 section 3.2.6. Only the identifier is read; the
/// optional `statementInfo` is deliberately not interpreted, because every
/// statement type has its own body and guessing at one would be worse than
/// reporting the claim.
#[derive(Clone, Debug, der::Sequence)]
struct QcStatement {
    statement_id: ObjectIdentifier,
    #[asn1(optional = "true")]
    statement_info: Option<der::Any>,
}
/// Critical extensions whose semantics this validator actually implements.
///
/// RFC 5280 requires a verifier to reject a certificate carrying a critical
/// extension it does not process. The list is therefore exactly what is
/// processed below, and nothing else: `subjectKeyIdentifier`,
/// `authorityKeyIdentifier`, `cRLDistributionPoints`, `authorityInfoAccess`
/// and QCStatements are non-critical in practice and are *not* listed, so a
/// certificate that marks one critical fails closed. `certificatePolicies` is
/// likewise absent: policy processing is not implemented, so a critical
/// policies extension must not be waved through.
const IMPLEMENTED_CRITICAL: &[ObjectIdentifier] = &[
    BasicConstraints::OID,
    KeyUsage::OID,
    NameConstraints::OID,
    SubjectAltName::OID,
    OID_EXT_KEY_USAGE,
];

impl ParsedCertificate {
    /// Whether `basicConstraints` marks this a CA. A malformed extension reads
    /// as "not a CA", which only ever moves the certificate later in the
    /// signer-selection order; the path check reports the malformation itself.
    pub fn is_certificate_authority(&self) -> bool {
        self.extension::<BasicConstraints>()
            .ok()
            .flatten()
            .is_some_and(|constraints| constraints.ca)
    }

    /// One extension, distinguishing "absent" from "present but malformed".
    ///
    /// Treating a decoding failure as absence would make a corrupt `keyUsage`
    /// or `nameConstraints` silently vanish, which is the wrong direction for
    /// every one of them.
    pub(super) fn extension<T: AssociatedOid + for<'a> Decode<'a>>(&self) -> Result<Option<T>, ()> {
        let Some(extensions) = self.certificate.tbs_certificate.extensions.as_ref() else {
            return Ok(None);
        };
        let Some(extension) = extensions
            .iter()
            .find(|extension| extension.extn_id == T::OID)
        else {
            return Ok(None);
        };
        T::from_der(extension.extn_value.as_bytes())
            .map(Some)
            .map_err(|_| ())
    }

    pub(crate) fn is_critical(&self, oid: ObjectIdentifier) -> bool {
        self.certificate
            .tbs_certificate
            .extensions
            .as_ref()
            .is_some_and(|extensions| {
                extensions
                    .iter()
                    .any(|extension| extension.extn_id == oid && extension.critical)
            })
    }

    pub(super) fn unimplemented_critical(&self) -> bool {
        self.certificate
            .tbs_certificate
            .extensions
            .as_ref()
            .is_some_and(|extensions| {
                extensions.iter().any(|extension| {
                    extension.critical && !IMPLEMENTED_CRITICAL.contains(&extension.extn_id)
                })
            })
    }

    /// The `keyUsage` extension, distinguishing absent from malformed.
    pub(crate) fn key_usage(&self) -> Result<Option<KeyUsage>, ()> {
        self.extension::<KeyUsage>()
    }

    /// The ETSI EN 319 412-5 / RFC 3739 `QCStatements` this certificate
    /// asserts, as the OIDs of the statements it carries.
    ///
    /// A statement is a **claim by the issuer**, never a determination: it
    /// says what the CA asserts, and only a trusted list can say whether the
    /// CA was entitled to assert it. `Err` means the extension is present but
    /// malformed, which is not the same as absent.
    pub(crate) fn qc_statement_oids(&self) -> Result<Option<Vec<ObjectIdentifier>>, ()> {
        let Some(extensions) = self.certificate.tbs_certificate.extensions.as_ref() else {
            return Ok(None);
        };
        let Some(extension) = extensions
            .iter()
            .find(|extension| extension.extn_id == OID_QC_STATEMENTS)
        else {
            return Ok(None);
        };
        let statements =
            Vec::<QcStatement>::from_der(extension.extn_value.as_bytes()).map_err(|_| ())?;
        if statements.len() > MAX_QC_STATEMENTS {
            return Err(());
        }
        Ok(Some(
            statements
                .into_iter()
                .map(|statement| statement.statement_id)
                .collect(),
        ))
    }

    /// The extended key usages, if the extension is present.
    pub(crate) fn extended_key_usages(&self) -> Result<Option<Vec<ObjectIdentifier>>, ()> {
        let Some(extensions) = self.certificate.tbs_certificate.extensions.as_ref() else {
            return Ok(None);
        };
        let Some(extension) = extensions
            .iter()
            .find(|extension| extension.extn_id == OID_EXT_KEY_USAGE)
        else {
            return Ok(None);
        };
        Vec::<ObjectIdentifier>::from_der(extension.extn_value.as_bytes())
            .map(Some)
            .map_err(|_| ())
    }

    /// The raw `subjectKeyIdentifier` octets, when the certificate carries the
    /// extension.
    ///
    /// A trusted list may name a service by SKI alone, which is why this is
    /// public. It is an identifier a CA chose, not a proof of anything, so it
    /// may corroborate a chain and never grant trust to one.
    pub fn subject_key_identifier(&self) -> Option<Vec<u8>> {
        let extensions = self.certificate.tbs_certificate.extensions.as_ref()?;
        let extension = extensions
            .iter()
            .find(|extension| extension.extn_id == OID_SUBJECT_KEY_IDENTIFIER)?;
        der::asn1::OctetString::from_der(extension.extn_value.as_bytes())
            .ok()
            .map(|value| value.as_bytes().to_vec())
    }

    /// The `http`/`https` CRL distribution point URLs this certificate
    /// publishes, in the order it publishes them.
    ///
    /// Only the `fullName`/`uniformResourceIdentifier` form is read: a
    /// distribution point given as a name relative to the CRL issuer is one
    /// this build refuses to use even when it is handed the file, so
    /// constructing a URL for it would be pointless. The scheme is never
    /// upgraded or rewritten — what a caller may fetch is exactly what the CA
    /// published.
    pub fn crl_distribution_urls(&self) -> Vec<String> {
        let Some(points) = self.crl_distribution_points() else {
            return Vec::new();
        };
        let mut urls = Vec::new();
        for point in points {
            let Some(x509_cert::ext::pkix::name::DistributionPointName::FullName(names)) =
                point.distribution_point.as_ref()
            else {
                continue;
            };
            for name in names {
                if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) =
                    name
                {
                    let url = uri.as_str().to_owned();
                    if !urls.contains(&url) {
                        urls.push(url);
                    }
                }
            }
        }
        urls
    }

    /// The OCSP responder URLs this certificate's `authorityInfoAccess`
    /// extension publishes, in order.
    pub fn ocsp_responder_urls(&self) -> Vec<String> {
        let Some(extensions) = self.certificate.tbs_certificate.extensions.as_ref() else {
            return Vec::new();
        };
        let Some(extension) = extensions
            .iter()
            .find(|extension| extension.extn_id == OID_AUTHORITY_INFO_ACCESS)
        else {
            return Vec::new();
        };
        let Ok(descriptions) = Vec::<x509_cert::ext::pkix::AccessDescription>::from_der(
            extension.extn_value.as_bytes(),
        ) else {
            return Vec::new();
        };
        let mut urls = Vec::new();
        for description in descriptions {
            if description.access_method != OID_AD_OCSP {
                continue;
            }
            if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) =
                &description.access_location
            {
                let url = uri.as_str().to_owned();
                if !urls.contains(&url) {
                    urls.push(url);
                }
            }
        }
        urls
    }
}
