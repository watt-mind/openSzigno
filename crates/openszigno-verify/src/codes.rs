//! Stable check codes, statuses, and verdicts.
//!
//! Codes are stable strings that never change meaning. A consumer must treat an
//! unknown code as blocking unless its status is `passed`.

use serde::Serialize;

/// The outcome of one check.
///
/// `unknown` means the tool could not determine the answer; it is never a
/// substitute for `failed`, because "I do not know" and "this is forged" are
/// different statements.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Failed,
    Skipped,
    Unknown,
}

impl CheckStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Unknown => "unknown",
        }
    }
}

/// The ETSI EN 319 102-1 status vocabulary, minus the states this phase cannot
/// reach.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// TOTAL-PASSED. Unreachable in phase 1 by construction.
    Valid,
    /// INDETERMINATE.
    Indeterminate,
    /// TOTAL-FAILED.
    Invalid,
}

impl Verdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Indeterminate => "indeterminate",
            Self::Invalid => "invalid",
        }
    }

    /// The worse of two verdicts: `invalid` is worse than `indeterminate`,
    /// which is worse than `valid`.
    pub fn worst(self, other: Self) -> Self {
        if other > self { other } else { self }
    }
}

macro_rules! check_codes {
    ($( $variant:ident => $text:literal ),* $(,)?) => {
        /// Every check code this crate can emit.
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
        #[serde(into = "&'static str")]
        pub enum CheckCode { $( $variant, )* }

        impl CheckCode {
            pub const fn as_str(self) -> &'static str {
                match self { $( Self::$variant => $text, )* }
            }

            /// Every code, for documentation and test coverage.
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )* ];
        }
    };
}

check_codes! {
    // Dossier level.
    NoSignatures => "no_signatures",
    SignatureCountWithinLimits => "signature_count_within_limits",
    SignatureLimitExceeded => "signature_limit_exceeded",

    // Stage A: structure and policy.
    SigStructure => "sig_structure",
    SigStructureInvalid => "sig_structure_invalid",
    SigPlacement => "sig_placement",
    SigPlacementInvalid => "sig_placement_invalid",
    C14nMethodAllowed => "c14n_method_allowed",
    C14nUnsupported => "c14n_unsupported",
    SignatureAlgorithmAllowed => "signature_algorithm_allowed",
    DigestAlgorithmAllowed => "digest_algorithm_allowed",
    AlgorithmRejected => "algorithm_rejected",
    AlgorithmLegacyAllowed => "algorithm_legacy_allowed",
    TransformsAllowed => "transforms_allowed",
    TransformNotAllowed => "transform_not_allowed",
    ReferencesSameDocument => "references_same_document",
    ReferenceExternal => "reference_external",
    ReferencesResolve => "references_resolve",
    ReferenceUnresolved => "reference_unresolved",
    ReferenceScopeComplete => "reference_scope_complete",
    ReferenceScopeIncomplete => "reference_scope_incomplete",
    ReferenceScopeUnknown => "reference_scope_unknown",

    // Stage B: the XMLDSig cryptographic core.
    ReferenceDigestOk => "reference_digest_ok",
    ReferenceDigestMismatch => "reference_digest_mismatch",
    SignedInfoCanonicalization => "signedinfo_canonicalization",
    SignedInfoCanonicalizationFailed => "signedinfo_canonicalization_failed",
    SignatureValueOk => "signature_value_ok",
    SignatureValueInvalid => "signature_value_invalid",

    // Stage C: XAdES, detected only in phase 1.
    XadesPresent => "xades_present",
    XadesAbsent => "xades_absent",
    XadesNotValidated => "xades_not_validated",

    // Stage D: certificate path.
    SigningCertificateAvailable => "signing_certificate_available",
    SigningCertificateMissing => "signing_certificate_missing",
    SigningTimePresent => "signing_time_present",
    CertMalformed => "cert_malformed",
    CertPathOk => "cert_path_ok",
    CertPathUnknown => "cert_path_unknown",
    CertPathUntrusted => "cert_path_untrusted",
    CertPathSearchExhausted => "cert_path_search_exhausted",
    CertPathLengthExceeded => "cert_path_length_exceeded",
    CertExpired => "cert_expired",
    CertNotYetValid => "cert_not_yet_valid",
    CertSignatureInvalid => "cert_signature_invalid",
    CertAlgorithmRejected => "cert_algorithm_rejected",
    CertKeyUsageInvalid => "cert_key_usage_invalid",
    CertBasicConstraintsInvalid => "cert_basic_constraints_invalid",
    CertNameConstraintViolation => "cert_name_constraint_violation",
    CertUnsupportedCriticalExtension => "cert_unsupported_critical_extension",

    // Stages E and F: out of phase-1 scope, reported rather than ignored.
    RevocationNotChecked => "revocation_not_checked",
    TimestampNotChecked => "timestamp_not_checked",
}

impl From<CheckCode> for &'static str {
    fn from(code: CheckCode) -> Self {
        code.as_str()
    }
}

/// One emitted check.
#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub code: CheckCode,
    pub status: CheckStatus,
    /// Human text. Never stable, and never contains payload content, input
    /// paths, or signer data.
    pub message: String,
}

impl Check {
    pub fn new(code: CheckCode, status: CheckStatus, message: impl Into<String>) -> Self {
        Self {
            code,
            status,
            message: message.into(),
        }
    }

    pub fn passed(code: CheckCode, message: impl Into<String>) -> Self {
        Self::new(code, CheckStatus::Passed, message)
    }

    pub fn failed(code: CheckCode, message: impl Into<String>) -> Self {
        Self::new(code, CheckStatus::Failed, message)
    }

    pub fn skipped(code: CheckCode, message: impl Into<String>) -> Self {
        Self::new(code, CheckStatus::Skipped, message)
    }

    pub fn unknown(code: CheckCode, message: impl Into<String>) -> Self {
        Self::new(code, CheckStatus::Unknown, message)
    }
}

/// Fold a list of checks into a verdict.
///
/// One `failed` makes the verdict `invalid`. Anything that is not `passed`
/// keeps it below `valid`. The function is monotone: adding a check can only
/// lower the verdict.
pub fn verdict_of(checks: &[Check]) -> Verdict {
    let mut verdict = Verdict::Valid;
    for check in checks {
        verdict = verdict.worst(match check.status {
            CheckStatus::Passed => Verdict::Valid,
            CheckStatus::Failed => Verdict::Invalid,
            CheckStatus::Skipped | CheckStatus::Unknown => Verdict::Indeterminate,
        });
    }
    verdict
}
