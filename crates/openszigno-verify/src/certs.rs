//! X.509 parsing, public-key signature verification, and RFC 5280 path
//! validation.
//!
//! There is no general-purpose certification-path-validation crate in Rust that
//! fits eIDAS signing certificates (`rustls-webpki` is Web-PKI shaped and wants
//! a DNS name), so this is hand-written on `x509-cert`. That is a liability and
//! is documented as one: the implemented subset is deliberately narrow, every
//! rule below is explicit, and anything unrecognised is refused rather than
//! ignored.

use std::collections::BTreeSet;

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{Decode, Encode};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, NameConstraints, SubjectAltName};
use x509_cert::name::Name;

use crate::codes::{Check, CheckCode};
use crate::policy::{Digest as PolicyDigest, MIN_RSA_BITS, SignatureScheme, VerifyLimits};
use crate::trust::{UnixTime, format_rfc3339};

const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_ANY_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");
/// `id-kp-timeStamping`, RFC 3161 section 2.3.
pub const OID_KP_TIME_STAMPING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
/// `id-kp-documentSigning`, RFC 9336. The purpose that exists precisely for
/// signing documents, rather than for authenticating a host or a mailbox.
pub const OID_KP_DOCUMENT_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.36");
/// `szOID_KP_DOCUMENT_SIGNING`, Microsoft's "Document Signing" extended key
/// usage from its private arc (`1.3.6.1.4.1.311.10.3.12`). It predates RFC
/// 9336 by two decades and is what qualified-signature CAs actually put in
/// signing certificates, so it is accepted for the same purpose.
pub const OID_MS_DOCUMENT_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.3.12");

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

/// The largest number of candidate expansions one path search may perform.
///
/// The per-path and per-length bounds are not enough on their own: a bag of
/// certificates whose subject and issuer names all match, and which never
/// reaches an anchor, produces no completed paths at all while the search
/// explores exponentially many prefixes. This bounds the work itself.
const MAX_PATH_EXPANSIONS: usize = 256;

/// The public summary of a certificate.
///
/// Deliberately limited: subject and issuer common names, serial, validity,
/// key algorithm and size, and the SHA-256 fingerprint. Full distinguished
/// names, subject alternative names, and any other identifying material stay
/// out of the report, and none of these values is ever interpolated into a
/// check message.
#[derive(Clone, Debug, Serialize)]
pub struct CertificateSummary {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub key_algorithm: Option<&'static str>,
    pub key_bits: Option<u32>,
    pub sha256_fingerprint: String,
    /// Never determined in phase 1; a trusted-list snapshot is phase 3.
    pub qualified: Option<bool>,
}

/// Where a certificate offered for path building came from.
///
/// Only the trust store can supply an anchor. A certificate found in the
/// dossier is always an untrusted candidate, however it is signed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateSource {
    /// `ds:KeyInfo/ds:X509Data/ds:X509Certificate`.
    KeyInfo,
    /// `xades:CertificateValues/xades:EncapsulatedX509Certificate`, and any
    /// other encapsulated certificate under the signature's XAdES properties.
    CertificateValues,
    /// A file in the `--trust-store` directory.
    TrustStore,
    /// The `certificates` set of an RFC 3161 timestamp token.
    TimestampToken,
}

/// What a built path is being validated *for*.
///
/// The purpose decides which critical `extendedKeyUsage` a certificate in the
/// path may carry. It never relaxes anything else: every other rule in
/// [`check_path`] applies identically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathPurpose {
    /// A signing certificate for a `ds:Signature`.
    Signing,
    /// A timestamp authority certificate, which RFC 3161 requires to carry a
    /// critical `extendedKeyUsage` of exactly `id-kp-timeStamping`.
    TimeStamping,
}

/// One link of a reported chain.
#[derive(Clone, Debug, Serialize)]
pub struct ChainEntry {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub is_trust_anchor: bool,
    pub source: CertificateSource,
}

/// A parsed certificate plus the DER it came from and where it was found.
#[derive(Clone, Debug)]
pub struct ParsedCertificate {
    pub der: Vec<u8>,
    pub certificate: Certificate,
    pub source: CertificateSource,
}

impl ParsedCertificate {
    pub fn from_der(der: &[u8], source: CertificateSource) -> Option<Self> {
        Certificate::from_der(der).ok().map(|certificate| Self {
            der: der.to_vec(),
            certificate,
            source,
        })
    }

    /// Whether the certificate names itself as its own issuer.
    ///
    /// This is how the trust-store loader tells an anchor from an intermediate
    /// a caller dropped into the same directory. The self-signature itself is
    /// deliberately *not* verified: RFC 5280 does not require it of an anchor,
    /// and demanding it would reject a legitimate root that signed itself with
    /// an algorithm outside this tool's allowlist. It is only a
    /// classification, never a grant of trust: a self-signed certificate found
    /// inside a dossier is never an anchor.
    pub fn is_self_signed(&self) -> bool {
        self.subject_der() == self.issuer_der()
    }

    /// Whether `basicConstraints` marks this a CA. A malformed extension reads
    /// as "not a CA", which only ever moves the certificate later in the
    /// signer-selection order; the path check reports the malformation itself.
    pub fn is_certificate_authority(&self) -> bool {
        self.extension::<BasicConstraints>()
            .ok()
            .flatten()
            .is_some_and(|constraints| constraints.ca)
    }

    fn chain_entry(&self, is_trust_anchor: bool) -> ChainEntry {
        let tbs = &self.certificate.tbs_certificate;
        ChainEntry {
            subject_cn: common_name(&tbs.subject),
            issuer_cn: common_name(&tbs.issuer),
            serial_hex: hex(tbs.serial_number.as_bytes()),
            not_before: format_rfc3339(unix_time(tbs.validity.not_before)),
            not_after: format_rfc3339(unix_time(tbs.validity.not_after)),
            is_trust_anchor,
            source: self.source,
        }
    }

    pub fn summary(&self) -> CertificateSummary {
        let tbs = &self.certificate.tbs_certificate;
        let (algorithm, bits) = key_algorithm(&self.certificate);
        CertificateSummary {
            subject_cn: common_name(&tbs.subject),
            issuer_cn: common_name(&tbs.issuer),
            serial_hex: hex(tbs.serial_number.as_bytes()),
            not_before: format_rfc3339(unix_time(tbs.validity.not_before)),
            not_after: format_rfc3339(unix_time(tbs.validity.not_after)),
            key_algorithm: algorithm,
            key_bits: bits,
            sha256_fingerprint: hex(&Sha256::digest(&self.der)),
            qualified: None,
        }
    }

    pub(crate) fn subject_der(&self) -> Vec<u8> {
        self.certificate
            .tbs_certificate
            .subject
            .to_der()
            .unwrap_or_default()
    }

    pub(crate) fn issuer_der(&self) -> Vec<u8> {
        self.certificate
            .tbs_certificate
            .issuer
            .to_der()
            .unwrap_or_default()
    }

    /// One extension, distinguishing "absent" from "present but malformed".
    ///
    /// Treating a decoding failure as absence would make a corrupt `keyUsage`
    /// or `nameConstraints` silently vanish, which is the wrong direction for
    /// every one of them.
    fn extension<T: AssociatedOid + for<'a> Decode<'a>>(&self) -> Result<Option<T>, ()> {
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

    fn unimplemented_critical(&self) -> bool {
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
}

/// Read one or more certificates from a PEM or DER buffer.
///
/// A file holding several PEM blocks yields several certificates; a DER file
/// yields exactly one. **Every entry is parsed as an X.509 certificate here**,
/// so a store that loads is a store whose every byte was understood: a
/// half-loaded trust store would silently change what "trusted" means. The
/// error names the entry's ordinal, never the file, because the path may be
/// private.
pub fn certificates_from_bytes(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let text = std::str::from_utf8(bytes).ok();
    if let Some(text) = text.filter(|text| text.contains("-----BEGIN")) {
        let mut certificates = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let tail = &rest[start..];
            let end = tail
                .find("-----END CERTIFICATE-----")
                .ok_or_else(|| "a PEM block is not terminated".to_owned())?;
            let block = &tail[..end + "-----END CERTIFICATE-----".len()];
            let ordinal = certificates.len() + 1;
            let (label, der) = pem_rfc7468::decode_vec(block.as_bytes())
                .map_err(|_| format!("PEM block {ordinal} is malformed"))?;
            if label != "CERTIFICATE" {
                return Err(format!("PEM block {ordinal} is not a certificate"));
            }
            Certificate::from_der(&der)
                .map_err(|_| format!("PEM block {ordinal} is not a valid X.509 certificate"))?;
            certificates.push(der);
            rest = &tail[end + "-----END CERTIFICATE-----".len()..];
        }
        if certificates.is_empty() {
            return Err("no certificate was found in the PEM file".to_owned());
        }
        return Ok(certificates);
    }
    Certificate::from_der(bytes)
        .map(|_| vec![bytes.to_vec()])
        .map_err(|_| "the file is neither PEM nor DER certificate data".to_owned())
}

/// The result of building and validating a certification path.
pub struct PathOutcome {
    pub code: CheckCode,
    pub message: String,
    pub chain: Vec<ChainEntry>,
    /// Non-blocking observations about the path the caller must still report:
    /// checks that are `unknown` rather than `failed`, so they cap the verdict
    /// without condemning the signature.
    pub advisories: Vec<Check>,
}

/// Build a path from `leaf` to one of `anchors` and validate it.
///
/// `candidates` are untrusted certificates offered for path building: the ones
/// in `ds:KeyInfo`, the ones encapsulated in the signature's XAdES
/// `CertificateValues`, and any non-self-signed file in the trust store.
/// **Only `anchors` can end a path.** A self-signed certificate found inside a
/// dossier is a candidate like any other and can never make itself trusted.
///
/// With no anchors configured the answer is `cert_path_unknown`, not
/// `cert_path_untrusted`: the tool does not know, and saying "invalid" would be
/// as wrong as saying "valid".
pub fn validate_path(
    leaf: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    time: UnixTime,
    limits: &VerifyLimits,
    purpose: PathPurpose,
) -> PathOutcome {
    let leaf_only = vec![leaf.chain_entry(false)];
    if anchors.is_empty() {
        return PathOutcome {
            code: CheckCode::CertPathUnknown,
            message: "no trust anchors were configured, so the chain could not be checked"
                .to_owned(),
            chain: leaf_only,
            advisories: Vec::new(),
        };
    }

    let mut pool: Vec<(&ParsedCertificate, bool)> = Vec::new();
    for certificate in candidates.iter().take(limits.max_certificates) {
        // The leaf is never its own issuer candidate, and a certificate the
        // trust store already anchors is used in that role only: otherwise a
        // dossier's copy of an anchor would appear twice in the same path.
        let is_anchor = anchors.iter().any(|anchor| anchor.der == certificate.der);
        if certificate.der != leaf.der && !is_anchor {
            pool.push((certificate, false));
        }
    }
    for certificate in anchors.iter().take(limits.max_certificates) {
        pool.push((certificate, true));
    }
    let considered = pool.len();

    let mut paths: Vec<Vec<usize>> = Vec::new();
    let mut chain = vec![usize::MAX];
    let mut expansions = 0usize;
    // `usize::MAX` marks the leaf, which is not in the pool.
    let exhausted = build_paths(leaf, &pool, &mut chain, &mut paths, limits, &mut expansions);

    if paths.is_empty() {
        if exhausted {
            return PathOutcome {
                code: CheckCode::CertPathSearchExhausted,
                message: format!(
                    "path building gave up after {MAX_PATH_EXPANSIONS} expansions over {considered} candidate certificates"
                ),
                chain: leaf_only,
                advisories: Vec::new(),
            };
        }
        // CA names are public information a caller needs in order to fix a
        // trust store, so the issuer that could not be chained is named. No
        // end-entity detail beyond the subject CN already reported is added.
        let dangling = dangling_issuer(leaf, &pool, limits);
        let named = dangling
            .map(|name| format!("; the highest certificate reached names issuer CN {name}"))
            .unwrap_or_default();
        return PathOutcome {
            code: CheckCode::CertPathUntrusted,
            message: format!(
                "no path from the signing certificate to a configured trust anchor was found after considering {considered} candidate certificates{named}"
            ),
            chain: leaf_only,
            advisories: Vec::new(),
        };
    }

    let mut first_failure: Option<PathOutcome> = None;
    for path in paths {
        let certificates: Vec<&ParsedCertificate> = std::iter::once(leaf)
            .chain(path.iter().skip(1).map(|index| pool[*index].0))
            .collect();
        let entries: Vec<ChainEntry> = certificates
            .iter()
            .enumerate()
            .map(|(position, certificate)| {
                certificate.chain_entry(position + 1 == certificates.len())
            })
            .collect();
        match check_path(&certificates, time, purpose) {
            Ok(advisories) => {
                return PathOutcome {
                    code: CheckCode::CertPathOk,
                    message: format!(
                        "path of length {} built to a configured trust anchor",
                        certificates.len()
                    ),
                    chain: entries,
                    advisories,
                };
            }
            Err((code, message)) => {
                if first_failure.is_none() {
                    first_failure = Some(PathOutcome {
                        code,
                        message,
                        chain: entries,
                        advisories: Vec::new(),
                    });
                }
            }
        }
    }
    first_failure.unwrap_or(PathOutcome {
        code: CheckCode::CertPathUntrusted,
        message: "no acceptable path to a configured trust anchor was found".to_owned(),
        chain: leaf_only,
        advisories: Vec::new(),
    })
}

/// Depth-first path building, bounded by chain length, candidate count, and —
/// crucially — the total number of expansions.
///
/// Returns whether the expansion budget ran out, which is a distinct outcome
/// from "no path exists": the tool stopped looking rather than concluded.
fn build_paths(
    leaf: &ParsedCertificate,
    pool: &[(&ParsedCertificate, bool)],
    chain: &mut Vec<usize>,
    paths: &mut Vec<Vec<usize>>,
    limits: &VerifyLimits,
    expansions: &mut usize,
) -> bool {
    if paths.len() >= limits.max_paths {
        return false;
    }
    let current = chain
        .last()
        .and_then(|index| (*index != usize::MAX).then(|| pool[*index].0))
        .unwrap_or(leaf);
    // Completion is checked *before* the length bound, so a chain of exactly
    // `max_chain_length` certificates that ends at an anchor is a path rather
    // than one the search refused to look at: a limit of 8 admits 8, not 7.
    if chain.len() > 1 && pool[*chain.last().expect("chain is not empty")].1 {
        paths.push(chain.clone());
        return false;
    }
    if chain.len() >= limits.max_chain_length {
        return false;
    }
    let issuer_der = current.issuer_der();
    let mut exhausted = false;
    for (index, (candidate, _)) in pool.iter().enumerate() {
        if chain.contains(&index) {
            continue;
        }
        if candidate.subject_der() != issuer_der {
            continue;
        }
        *expansions += 1;
        if *expansions > MAX_PATH_EXPANSIONS {
            return true;
        }
        chain.push(index);
        exhausted |= build_paths(leaf, pool, chain, paths, limits, expansions);
        chain.pop();
        if exhausted || paths.len() >= limits.max_paths {
            return exhausted;
        }
    }
    exhausted
}

/// Follow one greedy chain upwards and report the issuer CN of the highest
/// certificate reached, which is the name a caller needs to add to the store.
fn dangling_issuer(
    leaf: &ParsedCertificate,
    pool: &[(&ParsedCertificate, bool)],
    limits: &VerifyLimits,
) -> Option<String> {
    let mut current = leaf;
    let mut seen: Vec<Vec<u8>> = vec![leaf.der.clone()];
    while seen.len() < limits.max_chain_length {
        let issuer_der = current.issuer_der();
        let next = pool
            .iter()
            .map(|(certificate, _)| *certificate)
            .find(|candidate| {
                candidate.subject_der() == issuer_der && !seen.contains(&candidate.der)
            });
        match next {
            Some(next) => {
                seen.push(next.der.clone());
                current = next;
            }
            None => break,
        }
    }
    common_name(&current.certificate.tbs_certificate.issuer)
}

/// Apply the implemented subset of RFC 5280 section 6.1 to one built path.
///
/// `path[0]` is the end-entity certificate and the last element is the trust
/// anchor. Every rule is explicit and every unimplemented case fails closed.
fn check_path(
    path: &[&ParsedCertificate],
    time: UnixTime,
    purpose: PathPurpose,
) -> Result<Vec<Check>, (CheckCode, String)> {
    let malformed = || {
        (
            CheckCode::CertMalformed,
            "a certificate in the path carries a malformed extension".to_owned(),
        )
    };

    for certificate in path {
        if certificate.unimplemented_critical() {
            return Err((
                CheckCode::CertUnsupportedCriticalExtension,
                "a certificate in the path marks an extension critical whose semantics this validator does not implement"
                    .to_owned(),
            ));
        }
        let validity = &certificate.certificate.tbs_certificate.validity;
        if time < unix_time(validity.not_before) {
            return Err((
                CheckCode::CertNotYetValid,
                "a certificate in the path was not yet valid at the validation time".to_owned(),
            ));
        }
        if time > unix_time(validity.not_after) {
            return Err((
                CheckCode::CertExpired,
                "a certificate in the path had expired at the validation time".to_owned(),
            ));
        }
    }

    // The end-entity certificate's extended key usage, which RFC 5280 section
    // 4.2.1.12 makes a restriction on what the key may be used for **whether or
    // not the extension is marked critical**. An absent extension imposes no
    // restriction and is accepted; a present one must name a purpose that
    // covers this use:
    //
    // - `anyExtendedKeyUsage`, which waives the restriction;
    // - `id-kp-documentSigning` (RFC 9336), the purpose that exists for exactly
    //   this;
    // - `id-kp-timeStamping`, but only when the path is being validated for a
    //   timestamp authority, where RFC 3161 additionally requires it to be the
    //   *only* purpose and to be critical (checked on the token's own
    //   certificate).
    //
    // `id-kp-emailProtection` is not one of them: signing a message to a
    // mailbox is not signing a document. Neither are `serverAuth`,
    // `clientAuth`, `codeSigning` and `OCSPSigning`.
    //
    // An EKU naming none of the accepted purposes is not automatically a
    // refusal, though. ETSI EN 319 412-2 makes `nonRepudiation`
    // (`contentCommitment`) *the* key-usage signal for a signing certificate,
    // and real qualified certificates pair it with an EKU that says
    // `emailProtection` and nothing else. Calling those signatures invalid
    // over a purpose field the issuer filled in loosely would be wrong. So:
    // with `nonRepudiation` asserted, an unrelated EKU downgrades to
    // `cert_key_usage_advisory` (`unknown`), which caps the verdict at
    // indeterminate and names what was found. Without `nonRepudiation` there
    // is no such signal, and the certificate is refused.
    let mut advisories: Vec<Check> = Vec::new();
    if let Some(usages) = path[0].extended_key_usages().map_err(|()| malformed())? {
        let permitted = usages.contains(&OID_ANY_EXTENDED_KEY_USAGE)
            || match purpose {
                PathPurpose::Signing => {
                    usages.contains(&OID_KP_DOCUMENT_SIGNING)
                        || usages.contains(&OID_MS_DOCUMENT_SIGNING)
                }
                PathPurpose::TimeStamping => usages.contains(&OID_KP_TIME_STAMPING),
            };
        let non_repudiation = path[0]
            .extension::<KeyUsage>()
            .map_err(|()| malformed())?
            .is_some_and(|usage| usage.non_repudiation());
        if !permitted {
            if purpose == PathPurpose::Signing && non_repudiation {
                advisories.push(Check::unknown(
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

    // A CA's extended key usage is only enforced when it is marked critical.
    // RFC 5280 gives no path-processing rule for EKU in a CA certificate, and
    // real eIDAS hierarchies carry advisory sets there; refusing them would
    // reject chains that are correct. A CA that marks the extension critical
    // has asked to be taken at its word, and is.
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
            };
        if !permitted {
            return Err((
                CheckCode::CertKeyUsageInvalid,
                "a CA in the path has a critical extendedKeyUsage that does not permit this use"
                    .to_owned(),
            ));
        }
    }

    // Every link's signature, under the algorithm allowlist.
    for window in path.windows(2) {
        verify_certificate_signature(window[0], window[1])?;
    }

    // Every non-leaf must be a CA that may sign certificates, and must respect
    // its own path-length constraint.
    for (position, certificate) in path.iter().enumerate().skip(1) {
        let basic = certificate
            .extension::<BasicConstraints>()
            .map_err(|()| malformed())?;
        match &basic {
            Some(constraints) if constraints.ca => {}
            _ => {
                return Err((
                    CheckCode::CertBasicConstraintsInvalid,
                    "an issuing certificate in the path is not marked as a CA".to_owned(),
                ));
            }
        }
        if let Some(usage) = certificate
            .extension::<KeyUsage>()
            .map_err(|()| malformed())?
            && !usage.key_cert_sign()
        {
            return Err((
                CheckCode::CertKeyUsageInvalid,
                "an issuing certificate in the path does not permit keyCertSign".to_owned(),
            ));
        }
        if let Some(limit) = basic.and_then(|constraints| constraints.path_len_constraint)
            && usize::from(limit) < position - 1
        {
            return Err((
                CheckCode::CertPathLengthExceeded,
                "a CA in the path is followed by more intermediates than its pathLenConstraint allows"
                    .to_owned(),
            ));
        }
    }

    // The signer's own key usage.
    if let Some(usage) = path[0].extension::<KeyUsage>().map_err(|()| malformed())?
        && !(usage.digital_signature() || usage.non_repudiation())
    {
        return Err((
            CheckCode::CertKeyUsageInvalid,
            "the signing certificate permits neither digitalSignature nor nonRepudiation"
                .to_owned(),
        ));
    }

    // Name constraints imposed by any CA apply to everything below it.
    for (position, certificate) in path.iter().enumerate().skip(1) {
        let Some(constraints) = certificate
            .extension::<NameConstraints>()
            .map_err(|()| malformed())?
        else {
            continue;
        };
        for subordinate in &path[..position] {
            check_name_constraints(subordinate, &constraints)?;
        }
    }
    Ok(advisories)
}

fn verify_certificate_signature(
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
) -> Result<(), (CheckCode, String)> {
    let scheme = match subject.certificate.signature_algorithm.oid {
        OID_SHA256_RSA => SignatureScheme::RsaPkcs1(PolicyDigest::Sha256),
        OID_SHA384_RSA => SignatureScheme::RsaPkcs1(PolicyDigest::Sha384),
        OID_SHA512_RSA => SignatureScheme::RsaPkcs1(PolicyDigest::Sha512),
        OID_ECDSA_SHA256 => SignatureScheme::Ecdsa(PolicyDigest::Sha256),
        OID_ECDSA_SHA384 => SignatureScheme::Ecdsa(PolicyDigest::Sha384),
        _ => {
            return Err((
                CheckCode::CertAlgorithmRejected,
                "a certificate in the path is signed with an algorithm outside the allowlist"
                    .to_owned(),
            ));
        }
    };
    let message = subject.certificate.tbs_certificate.to_der().map_err(|_| {
        (
            CheckCode::CertMalformed,
            "a certificate could not be re-encoded for signature checking".to_owned(),
        )
    })?;
    let signature = subject.certificate.signature.as_bytes().ok_or((
        CheckCode::CertMalformed,
        "a certificate signature is not a whole number of bytes".to_owned(),
    ))?;

    match verify_with_spki(&issuer.certificate, scheme, &message, signature, true) {
        Ok(()) => Ok(()),
        Err(VerifyError::WeakKey) => Err((
            CheckCode::CertAlgorithmRejected,
            "a certificate in the path uses a key below the minimum size".to_owned(),
        )),
        Err(VerifyError::UnsupportedKey) => Err((
            CheckCode::CertAlgorithmRejected,
            "a certificate in the path uses an unsupported public-key type".to_owned(),
        )),
        Err(_) => Err((
            CheckCode::CertSignatureInvalid,
            "a certificate in the path is not correctly signed by its issuer".to_owned(),
        )),
    }
}

/// RFC 5280 section 4.2.1.10 name-constraint processing.
///
/// Fails closed throughout: a constraint form this validator does not
/// implement, a name it cannot parse, and a permitted subtree of a type the
/// certificate carries but does not match are all violations.
fn check_name_constraints(
    certificate: &ParsedCertificate,
    constraints: &NameConstraints,
) -> Result<(), (CheckCode, String)> {
    let violation = || {
        (
            CheckCode::CertNameConstraintViolation,
            "a certificate in the path violates a name constraint imposed by a CA".to_owned(),
        )
    };
    let subject = &certificate.certificate.tbs_certificate.subject;
    let alternatives = certificate
        .extension::<SubjectAltName>()
        .map_err(|()| {
            (
                CheckCode::CertMalformed,
                "a certificate in the path carries a malformed subjectAltName".to_owned(),
            )
        })?
        .map(|san| san.0)
        .unwrap_or_default();

    // Every name the certificate asserts, as (kind, GeneralName).
    let mut names: Vec<GeneralName> = alternatives;
    if !subject.0.is_empty() {
        names.push(GeneralName::DirectoryName(subject.clone()));
    }

    for subtrees in [
        &constraints.excluded_subtrees,
        &constraints.permitted_subtrees,
    ]
    .into_iter()
    .flatten()
    {
        for subtree in subtrees {
            // An unimplemented constraint form must not be ignored: it may be
            // the only thing standing between this certificate and a name it
            // is not entitled to.
            if kind_of(&subtree.base).is_none() {
                return Err(violation());
            }
            // `minimum` and `maximum` are not implemented; RFC 5280 says both
            // MUST be absent, so a certificate that uses them fails closed.
            if subtree.minimum != 0 || subtree.maximum.is_some() {
                return Err(violation());
            }
        }
    }

    if let Some(excluded) = &constraints.excluded_subtrees {
        for subtree in excluded {
            for name in &names {
                if matches_general(&subtree.base, name)? {
                    return Err(violation());
                }
            }
        }
    }

    if let Some(permitted) = &constraints.permitted_subtrees {
        for name in &names {
            let Some(kind) = kind_of(name) else {
                // A name form the validator cannot evaluate, under a
                // constrained CA, fails closed.
                return Err(violation());
            };
            let same_kind: Vec<_> = permitted
                .iter()
                .filter(|subtree| kind_of(&subtree.base) == Some(kind))
                .collect();
            if same_kind.is_empty() {
                // This name form is unconstrained.
                continue;
            }
            let mut matched = false;
            for subtree in same_kind {
                if matches_general(&subtree.base, name)? {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err(violation());
            }
        }
    }
    Ok(())
}

/// The name forms this validator can evaluate. Anything else is `None`, which
/// every caller turns into a violation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NameKind {
    Dns,
    Rfc822,
    Uri,
    Directory,
    IpAddress,
}

fn kind_of(name: &GeneralName) -> Option<NameKind> {
    match name {
        GeneralName::DnsName(_) => Some(NameKind::Dns),
        GeneralName::Rfc822Name(_) => Some(NameKind::Rfc822),
        GeneralName::UniformResourceIdentifier(_) => Some(NameKind::Uri),
        GeneralName::DirectoryName(_) => Some(NameKind::Directory),
        GeneralName::IpAddress(_) => Some(NameKind::IpAddress),
        _ => None,
    }
}

fn matches_general(base: &GeneralName, name: &GeneralName) -> Result<bool, (CheckCode, String)> {
    let violation = || {
        (
            CheckCode::CertNameConstraintViolation,
            "a certificate in the path carries a name a constraint could not be evaluated against"
                .to_owned(),
        )
    };
    Ok(match (base, name) {
        (GeneralName::DnsName(base), GeneralName::DnsName(value)) => {
            dns_matches(base.as_str(), value.as_str())
        }
        (GeneralName::Rfc822Name(base), GeneralName::Rfc822Name(value)) => {
            rfc822_matches(base.as_str(), value.as_str())
        }
        (
            GeneralName::UniformResourceIdentifier(base),
            GeneralName::UniformResourceIdentifier(value),
        ) => {
            // The host is the only part a URI constraint applies to. A URI
            // with no host, or one whose host is an IP literal, cannot satisfy
            // a DNS-style constraint, and is a violation rather than a pass.
            let host = uri_host(value.as_str()).ok_or_else(violation)?;
            if host.is_ip_literal {
                return Err(violation());
            }
            dns_matches(base.as_str(), &host.host)
        }
        (GeneralName::DirectoryName(_), GeneralName::DirectoryName(subject)) => {
            matches_directory(base, subject)
        }
        (GeneralName::IpAddress(base), GeneralName::IpAddress(value)) => {
            ip_matches(base.as_bytes(), value.as_bytes()).ok_or_else(violation)?
        }
        _ => false,
    })
}

/// RFC 5280 dNSName matching: an exact host match, or a match on a label
/// boundary. `example.com` matches `host.example.com` but never
/// `notexample.com`. A leading dot on the constraint is accepted and means the
/// same thing, minus the exact match.
fn dns_matches(base: &str, value: &str) -> bool {
    let (base, allow_exact) = match base.strip_prefix('.') {
        Some(stripped) => (stripped, false),
        None => (base, true),
    };
    if base.is_empty() {
        return true;
    }
    if allow_exact && value.eq_ignore_ascii_case(base) {
        return true;
    }
    value.len() > base.len()
        && value.as_bytes()[value.len() - base.len() - 1] == b'.'
        && value[value.len() - base.len()..].eq_ignore_ascii_case(base)
}

/// RFC 5280 rfc822Name matching: a constraint with a local part is an exact
/// mailbox, a bare host is the exact host part, and a leading dot matches any
/// mailbox in that domain or below it.
fn rfc822_matches(base: &str, value: &str) -> bool {
    if base.contains('@') {
        return base.eq_ignore_ascii_case(value);
    }
    let Some((_, domain)) = value.rsplit_once('@') else {
        return false;
    };
    if base.starts_with('.') {
        return dns_matches(base, domain);
    }
    domain.eq_ignore_ascii_case(base)
}

struct UriHost {
    host: String,
    is_ip_literal: bool,
}

/// The host component of an absolute URI, or `None` when there is none.
///
/// Deliberately small and strict: anything this cannot parse confidently is a
/// name the constraint could not be evaluated against, which the caller turns
/// into a violation rather than a pass.
fn uri_host(uri: &str) -> Option<UriHost> {
    let after_scheme = uri.split_once("://")?.1;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .filter(|value| !value.is_empty())?;
    // Drop userinfo, which is not part of the host.
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, rest)| rest);
    if let Some(rest) = authority.strip_prefix('[') {
        // An IPv6 literal.
        let host = rest.split_once(']')?.0;
        return Some(UriHost {
            host: host.to_owned(),
            is_ip_literal: true,
        });
    }
    let host = authority
        .split(':')
        .next()
        .filter(|value| !value.is_empty())?;
    let is_ip_literal = !host.is_empty()
        && host
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
        && host.split('.').count() == 4;
    Some(UriHost {
        host: host.to_owned(),
        is_ip_literal,
    })
}

/// An iPAddress constraint is an address followed by a mask of the same width.
/// `None` means the encoding is not one this validator understands, which the
/// caller turns into a violation.
fn ip_matches(base: &[u8], value: &[u8]) -> Option<bool> {
    let width = match base.len() {
        8 => 4,
        32 => 16,
        _ => return None,
    };
    if value.len() != width {
        // A v4 address is simply outside a v6 constraint, and the other way
        // round; that is a clean non-match, not an encoding this cannot read.
        return Some(false);
    }
    let (network, mask) = base.split_at(width);
    Some(
        network
            .iter()
            .zip(mask.iter())
            .zip(value.iter())
            .all(|((network, mask), value)| network & mask == value & mask),
    )
}

/// A directoryName constraint matches when the base is an RDN-wise prefix of
/// the subject, comparing each RDN by its DER encoding.
fn matches_directory(base: &GeneralName, subject: &Name) -> bool {
    let GeneralName::DirectoryName(base) = base else {
        return false;
    };
    if base.0.len() > subject.0.len() {
        return false;
    }
    base.0.iter().zip(subject.0.iter()).all(|(left, right)| {
        left.to_der().unwrap_or_default() == right.to_der().unwrap_or_default()
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    BadSignature,
    UnsupportedKey,
    WeakKey,
    Malformed,
}

/// Verify `signature` over `message` with the certificate's public key.
///
/// `der_ecdsa` selects the ECDSA signature encoding: X.509 certificates carry a
/// DER `SEQUENCE`, XMLDSig carries the fixed-width `r || s` concatenation.
pub fn verify_with_spki(
    certificate: &Certificate,
    scheme: SignatureScheme,
    message: &[u8],
    signature: &[u8],
    der_ecdsa: bool,
) -> Result<(), VerifyError> {
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(VerifyError::Malformed)?;
    match spki.algorithm.oid {
        OID_RSA_ENCRYPTION => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::signature::Verifier;
            use rsa::traits::PublicKeyParts as _;
            let key =
                rsa::RsaPublicKey::from_pkcs1_der(key_bytes).map_err(|_| VerifyError::Malformed)?;
            if u32::try_from(key.n().bits()).unwrap_or(0) < MIN_RSA_BITS {
                return Err(VerifyError::WeakKey);
            }
            match scheme {
                SignatureScheme::RsaPkcs1(digest) => {
                    let signature = rsa::pkcs1v15::Signature::try_from(signature)
                        .map_err(|_| VerifyError::Malformed)?;
                    let verified = match digest {
                        PolicyDigest::Sha1 => rsa::pkcs1v15::VerifyingKey::<Sha1>::new(key)
                            .verify(message, &signature),
                        PolicyDigest::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key)
                            .verify(message, &signature),
                        PolicyDigest::Sha384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key)
                            .verify(message, &signature),
                        PolicyDigest::Sha512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key)
                            .verify(message, &signature),
                    };
                    verified.map_err(|_| VerifyError::BadSignature)
                }
                SignatureScheme::RsaPss(digest) => {
                    let signature = rsa::pss::Signature::try_from(signature)
                        .map_err(|_| VerifyError::Malformed)?;
                    let verified =
                        match digest {
                            PolicyDigest::Sha1 => {
                                rsa::pss::VerifyingKey::<Sha1>::new(key).verify(message, &signature)
                            }
                            PolicyDigest::Sha256 => rsa::pss::VerifyingKey::<Sha256>::new(key)
                                .verify(message, &signature),
                            PolicyDigest::Sha384 => rsa::pss::VerifyingKey::<Sha384>::new(key)
                                .verify(message, &signature),
                            PolicyDigest::Sha512 => rsa::pss::VerifyingKey::<Sha512>::new(key)
                                .verify(message, &signature),
                        };
                    verified.map_err(|_| VerifyError::BadSignature)
                }
                SignatureScheme::Ecdsa(_) => Err(VerifyError::UnsupportedKey),
            }
        }
        OID_EC_PUBLIC_KEY => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
                .ok_or(VerifyError::UnsupportedKey)?;
            let SignatureScheme::Ecdsa(digest) = scheme else {
                return Err(VerifyError::UnsupportedKey);
            };
            match (curve, digest) {
                (OID_PRIME256V1, PolicyDigest::Sha256) => {
                    use p256::ecdsa::signature::Verifier;
                    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                        .map_err(|_| VerifyError::Malformed)?;
                    let signature = if der_ecdsa {
                        p256::ecdsa::Signature::from_der(signature)
                    } else {
                        p256::ecdsa::Signature::from_slice(signature)
                    }
                    .map_err(|_| VerifyError::Malformed)?;
                    key.verify(message, &signature)
                        .map_err(|_| VerifyError::BadSignature)
                }
                (OID_SECP384R1, PolicyDigest::Sha384) => {
                    use p384::ecdsa::signature::Verifier;
                    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                        .map_err(|_| VerifyError::Malformed)?;
                    let signature = if der_ecdsa {
                        p384::ecdsa::Signature::from_der(signature)
                    } else {
                        p384::ecdsa::Signature::from_slice(signature)
                    }
                    .map_err(|_| VerifyError::Malformed)?;
                    key.verify(message, &signature)
                        .map_err(|_| VerifyError::BadSignature)
                }
                // A curve and digest that do not match is an algorithm
                // downgrade attempt, not a curve to guess at.
                _ => Err(VerifyError::UnsupportedKey),
            }
        }
        _ => Err(VerifyError::UnsupportedKey),
    }
}

/// The key algorithm and size a report exposes.
pub fn key_algorithm(certificate: &Certificate) -> (Option<&'static str>, Option<u32>) {
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let Some(key_bytes) = spki.subject_public_key.as_bytes() else {
        return (None, None);
    };
    match spki.algorithm.oid {
        OID_RSA_ENCRYPTION => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::traits::PublicKeyParts as _;
            let bits = rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
                .ok()
                .and_then(|key| u32::try_from(key.n().bits()).ok());
            (Some("rsa"), bits)
        }
        OID_EC_PUBLIC_KEY => {
            let bits = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
                .and_then(|curve| match curve {
                    OID_PRIME256V1 => Some(256),
                    OID_SECP384R1 => Some(384),
                    _ => None,
                });
            (Some("ec"), bits)
        }
        _ => (None, None),
    }
}

/// The subject or issuer common name, sanitised.
///
/// Certificate contents are attacker-controlled, so the value is limited in
/// length and stripped of anything that is not printable. It appears only in a
/// structured field, never in a message.
pub fn common_name(name: &Name) -> Option<String> {
    let mut found = None;
    for rdn in name.0.iter() {
        for attribute in rdn.0.iter() {
            if attribute.oid != OID_COMMON_NAME {
                continue;
            }
            let bytes = attribute.value.value();
            let text = std::str::from_utf8(bytes).ok()?;
            found = Some(sanitize(text));
        }
    }
    found
}

fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect()
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

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

fn unix_time(time: x509_cert::time::Time) -> UnixTime {
    time.to_unix_duration().as_secs() as i64
}

/// Certificates that appear in more than one place are deduplicated by DER, so
/// that a repeated `ds:X509Certificate` cannot inflate the path search.
pub fn dedup(certificates: Vec<ParsedCertificate>) -> Vec<ParsedCertificate> {
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    certificates
        .into_iter()
        .filter(|certificate| seen.insert(certificate.der.clone()))
        .collect()
}
