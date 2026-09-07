//! The pinned algorithm and transform policy, and the verification limits.
//!
//! The e-dossier container specification deliberately does not constrain
//! canonicalization, digest, or signature algorithms, so this policy is the only
//! defence against an algorithm downgrade. It is pinned in code, not
//! configurable: no flag in phase 1 can widen it.

use serde::Serialize;

use crate::c14n::{
    C14N_EXCLUSIVE, C14N_EXCLUSIVE_WITH_COMMENTS, C14N_INCLUSIVE, C14N_INCLUSIVE_WITH_COMMENTS,
};

/// The digest algorithms accepted for `ds:DigestMethod` and for certificate
/// signatures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Digest {
    /// Recognised, but admitted only under `--allow-legacy-algorithms`, and
    /// then only for diagnosis. See [`Digest::is_legacy`].
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Digest {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// Whether this digest is admitted only for diagnosis.
    ///
    /// A legacy algorithm never contributes a `passed` check, so it can only
    /// ever lower a verdict. Nothing here can turn a failure into a pass.
    pub const fn is_legacy(self) -> bool {
        matches!(self, Self::Sha1)
    }

    /// Map a `ds:DigestMethod` URI onto the policy.
    ///
    /// `None` means the URI is outside the allowlist entirely: MD5 and every
    /// unknown URI are refused unconditionally. SHA-1 maps to
    /// [`Digest::Sha1`], which the caller must still gate on
    /// `--allow-legacy-algorithms`.
    pub fn from_digest_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2000/09/xmldsig#sha1" => Some(Self::Sha1),
            "http://www.w3.org/2001/04/xmlenc#sha256" => Some(Self::Sha256),
            "http://www.w3.org/2001/04/xmldsig-more#sha384" => Some(Self::Sha384),
            "http://www.w3.org/2001/04/xmlenc#sha512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// The public-key signature schemes accepted for `ds:SignatureMethod`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureScheme {
    RsaPkcs1(Digest),
    RsaPss(Digest),
    Ecdsa(Digest),
}

impl SignatureScheme {
    pub const fn digest(self) -> Digest {
        match self {
            Self::RsaPkcs1(digest) | Self::RsaPss(digest) | Self::Ecdsa(digest) => digest,
        }
    }

    /// Whether this scheme is admitted only for diagnosis. Only the SHA-1
    /// variants are; a short RSA key, DSA, MD5, and every HMAC method stay
    /// refused whatever the flags say.
    pub const fn is_legacy(self) -> bool {
        self.digest().is_legacy()
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RsaPkcs1(Digest::Sha1) => "rsa-pkcs1-sha1",
            Self::RsaPss(Digest::Sha1) => "rsa-pss-sha1",
            Self::Ecdsa(Digest::Sha1) => "ecdsa-sha1",
            Self::RsaPkcs1(Digest::Sha256) => "rsa-pkcs1-sha256",
            Self::RsaPkcs1(Digest::Sha384) => "rsa-pkcs1-sha384",
            Self::RsaPkcs1(Digest::Sha512) => "rsa-pkcs1-sha512",
            Self::RsaPss(Digest::Sha256) => "rsa-pss-sha256",
            Self::RsaPss(Digest::Sha384) => "rsa-pss-sha384",
            Self::RsaPss(Digest::Sha512) => "rsa-pss-sha512",
            Self::Ecdsa(Digest::Sha256) => "ecdsa-sha256",
            Self::Ecdsa(Digest::Sha384) => "ecdsa-sha384",
            Self::Ecdsa(Digest::Sha512) => "ecdsa-sha512",
        }
    }

    /// Map a `ds:SignatureMethod` URI onto the policy.
    ///
    /// MD5 variants, DSA, and every HMAC method are absent on purpose: an HMAC
    /// "signature" in a dossier is a known attack shape. RSA with SHA-1 maps to
    /// a legacy scheme the caller must still gate on
    /// `--allow-legacy-algorithms`; by default it is refused rather than
    /// warned about.
    pub fn from_signature_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Some(Self::RsaPkcs1(Digest::Sha1)),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => {
                Some(Self::RsaPkcs1(Digest::Sha256))
            }
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => {
                Some(Self::RsaPkcs1(Digest::Sha384))
            }
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => {
                Some(Self::RsaPkcs1(Digest::Sha512))
            }
            "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" => {
                Some(Self::RsaPss(Digest::Sha256))
            }
            "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1" => {
                Some(Self::RsaPss(Digest::Sha384))
            }
            "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1" => {
                Some(Self::RsaPss(Digest::Sha512))
            }
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => {
                Some(Self::Ecdsa(Digest::Sha256))
            }
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => {
                Some(Self::Ecdsa(Digest::Sha384))
            }
            _ => None,
        }
    }
}

/// The transforms a `ds:Reference` may name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transform {
    EnvelopedSignature,
    Canonicalization(crate::c14n::C14nAlgorithm),
    Base64,
}

pub const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const BASE64_TRANSFORM: &str = "http://www.w3.org/2000/09/xmldsig#base64";

impl Transform {
    /// Map a transform URI onto the allowlist.
    ///
    /// XSLT, XPath, and XPath Filter 2.0 are absent by design: they turn a
    /// reference into an arbitrary computation over the document, which is the
    /// transform-abuse threat this project refuses outright.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            ENVELOPED_SIGNATURE => Some(Self::EnvelopedSignature),
            BASE64_TRANSFORM => Some(Self::Base64),
            other => crate::c14n::C14nAlgorithm::from_uri(other).map(Self::Canonicalization),
        }
    }
}

/// Verification limits, on top of the structural limits the core crate applies.
#[derive(Clone, Debug, Serialize)]
pub struct VerifyLimits {
    pub max_signatures: usize,
    pub max_references_per_signature: usize,
    pub max_transforms_per_reference: usize,
    pub max_certificates: usize,
    pub max_timestamps_per_signature: usize,
    pub max_chain_length: usize,
    pub max_paths: usize,
    /// The largest number of CRLs or OCSP responses consulted from any one
    /// source while answering about a single certificate.
    pub max_revocation_items: usize,
}

impl Default for VerifyLimits {
    fn default() -> Self {
        Self {
            max_signatures: 64,
            max_references_per_signature: 32,
            max_transforms_per_reference: 8,
            max_certificates: 64,
            max_timestamps_per_signature: 8,
            max_chain_length: 8,
            max_paths: 32,
            max_revocation_items: 256,
        }
    }
}

/// The policy as it appears in the machine-readable report.
#[derive(Clone, Debug, Serialize)]
pub struct PolicyReport {
    pub revocation: &'static str,
    pub trust_store: &'static str,
    /// The trusted lists the run used, if any: territory, sequence number, and
    /// issue date, so a result can cite exactly which snapshot it relied on.
    pub trust_lists: Vec<TrustListSnapshot>,
    pub trust_snapshot: Option<String>,
    pub legacy_algorithms_allowed: bool,
    pub digest_algorithms: Vec<&'static str>,
    pub signature_algorithms: Vec<&'static str>,
    pub c14n_algorithms: Vec<&'static str>,
    pub transforms: Vec<&'static str>,
}

/// One trusted list a run consulted, as the report cites it.
#[derive(Clone, Debug, Serialize)]
pub struct TrustListSnapshot {
    pub territory: Option<String>,
    pub sequence_number: Option<u64>,
    pub issue_date: Option<String>,
    pub next_update: Option<String>,
    pub anchors: usize,
    /// Whether the list's own XMLDSig signature was verified against a
    /// caller-supplied signer certificate.
    pub signature_verified: bool,
}

impl PolicyReport {
    pub fn new(
        trust_store_configured: bool,
        legacy_algorithms_allowed: bool,
        revocation: crate::trust::RevocationPolicy,
    ) -> Self {
        let mut digest_algorithms = vec!["sha256", "sha384", "sha512"];
        let mut signature_algorithms = vec![
            "rsa-pkcs1-sha256",
            "rsa-pkcs1-sha384",
            "rsa-pkcs1-sha512",
            "rsa-pss-sha256",
            "rsa-pss-sha384",
            "rsa-pss-sha512",
            "ecdsa-sha256",
            "ecdsa-sha384",
        ];
        if legacy_algorithms_allowed {
            // Reported so the machine output shows the policy that was
            // actually applied, not the default one.
            digest_algorithms.insert(0, "sha1");
            signature_algorithms.insert(0, "rsa-pkcs1-sha1");
        }
        Self {
            revocation: revocation.as_str(),
            trust_lists: Vec::new(),
            trust_store: if trust_store_configured {
                "configured"
            } else {
                "absent"
            },
            trust_snapshot: None,
            legacy_algorithms_allowed,
            digest_algorithms,
            signature_algorithms,
            c14n_algorithms: vec![
                C14N_INCLUSIVE,
                C14N_INCLUSIVE_WITH_COMMENTS,
                C14N_EXCLUSIVE,
                C14N_EXCLUSIVE_WITH_COMMENTS,
            ],
            transforms: vec![
                ENVELOPED_SIGNATURE,
                BASE64_TRANSFORM,
                C14N_INCLUSIVE,
                C14N_INCLUSIVE_WITH_COMMENTS,
                C14N_EXCLUSIVE,
                C14N_EXCLUSIVE_WITH_COMMENTS,
            ],
        }
    }
}

/// The smallest RSA modulus this tool will verify against.
pub const MIN_RSA_BITS: u32 = 2048;
