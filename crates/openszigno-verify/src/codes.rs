//! Stable check codes, statuses, and verdicts.
//!
//! Codes are stable strings that never change meaning. A consumer must treat an
//! unknown code as blocking unless its status is `passed`.
//!
//! [`CheckCode`], [`CheckStatus`] and [`Verdict`] are `#[non_exhaustive]`.
//! New check codes are emitted as the verifier learns to check more things, and
//! adding one is a normal, additive change here rather than a semver break, so
//! a downstream `match` on any of the three must carry a wildcard arm. Handle
//! the unknown arm conservatively: an unrecognised code or status is not a
//! passing one, and an unrecognised verdict is not `valid`. Read a code's
//! stable string with [`CheckCode::as_str`] and enumerate the codes this build
//! knows with [`CheckCode::ALL`].

use serde::Serialize;

/// The outcome of one check.
///
/// `unknown` means the tool could not determine the answer; it is never a
/// substitute for `failed`, because "I do not know" and "this is forged" are
/// different statements.
///
/// The enum is `#[non_exhaustive]`: match it with a wildcard arm and treat an
/// unrecognised status as blocking.
///
/// `info` is the one status that does not block: it exists so that a check
/// which only *reports* something — a certificate's loosely filled
/// `extendedKeyUsage`, the presence of a claimed signing time — can be emitted
/// without pretending the tool failed to determine anything. Every other
/// non-`passed` status keeps the verdict below `valid`, which is what makes
/// "`unknown` always blocks" true without exception.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckStatus {
    Passed,
    Failed,
    Skipped,
    Unknown,
    /// Purely informational, and deliberately non-blocking.
    Info,
}

impl CheckStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Unknown => "unknown",
            Self::Info => "info",
        }
    }

    /// Whether this status keeps the verdict below `valid`.
    pub const fn blocks(self) -> bool {
        matches!(self, Self::Failed | Self::Skipped | Self::Unknown)
    }
}

/// The ETSI EN 319 102-1 status vocabulary, minus the states this phase cannot
/// reach.
///
/// The enum is `#[non_exhaustive]`: match it with a wildcard arm and treat an
/// unrecognised verdict as not `valid`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Verdict {
    /// TOTAL-PASSED.
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
        ///
        /// The enum is `#[non_exhaustive]`, because a release that learns to
        /// check something new emits a new code for it. Match it with a
        /// wildcard arm, and treat an unknown code as blocking unless the
        /// [`CheckStatus`] beside it is `passed`. [`CheckCode::ALL`] lists
        /// every code the build in use knows.
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
        #[serde(into = "&'static str")]
        #[non_exhaustive]
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
    SignaturesUnsupported => "signatures_unsupported",

    // Document coverage: which modelled documents a signature actually covers.
    DocumentsAllCovered => "documents_all_covered",
    DocumentsUncovered => "documents_uncovered",
    DocumentsCoverageUndetermined => "documents_coverage_undetermined",

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

    // Countersignatures: ETSI EN 319 132-1 clause 5.2.7 (TS 101903 clause
    // 7.2.4) for the nested form, and the e-dossier specification's own
    // `es:SignatureProfile/es:Type` form.
    CountersignatureBindingOk => "countersignature_binding_ok",
    CountersignatureBindingMissing => "countersignature_binding_missing",
    CountersignatureBindingMismatch => "countersignature_binding_mismatch",
    NestedSignaturesUnsupported => "nested_signatures_unsupported",

    // Stage B: the XMLDSig cryptographic core.
    ReferenceDigestOk => "reference_digest_ok",
    ReferenceDigestMismatch => "reference_digest_mismatch",
    SignedInfoCanonicalization => "signedinfo_canonicalization",
    SignedInfoCanonicalizationFailed => "signedinfo_canonicalization_failed",
    SignatureValueOk => "signature_value_ok",
    SignatureValueInvalid => "signature_value_invalid",

    // Stage C: XAdES qualifying properties.
    XadesPresent => "xades_present",
    XadesAbsent => "xades_absent",
    XadesNotValidated => "xades_not_validated",
    XadesExtraQualifyingProperties => "xades_extra_qualifying_properties",
    XadesSigningCertificateBound => "xades_signing_certificate_bound",
    XadesSigningCertificateMismatch => "xades_signing_certificate_mismatch",
    XadesSigningCertificateAbsent => "xades_signing_certificate_absent",
    XadesSignaturePolicyImplied => "xades_signature_policy_implied",
    XadesSignaturePolicyExplicit => "xades_signature_policy_explicit",

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
    CertKeyUsageAdvisory => "cert_key_usage_advisory",
    CertBasicConstraintsInvalid => "cert_basic_constraints_invalid",
    CertNameConstraintViolation => "cert_name_constraint_violation",
    CertUnsupportedCriticalExtension => "cert_unsupported_critical_extension",

    // Stage E: revocation.
    RevocationPolicy => "revocation_policy",
    RevocationNotChecked => "revocation_not_checked",
    RevocationOk => "revocation_ok",
    CertRevoked => "cert_revoked",
    CertRevokedAfterValidationTime => "cert_revoked_after_validation_time",
    RevocationStatusUnknown => "revocation_status_unknown",
    RevocationStatusUnknownByResponder => "revocation_status_unknown_by_responder",
    RevocationDataStale => "revocation_data_stale",
    RevocationDataInvalid => "revocation_data_invalid",
    OcspResponderTrusted => "ocsp_responder_trusted",
    RevocationSourcesDisagree => "revocation_sources_disagree",
    OnlineFetchFailed => "online_fetch_failed",

    // Trusted lists (ETSI TS 119 612).
    TrustListLoaded => "trust_list_loaded",
    TrustListUnverified => "trust_list_unverified",
    TrustListSignatureOk => "trust_list_signature_ok",
    TrustListSignatureInvalid => "trust_list_signature_invalid",
    TrustListServiceNotGranted => "trust_list_service_not_granted",
    CertificateQualified => "certificate_qualified",
    CertificateNotQualified => "certificate_not_qualified",
    CertificateQualifiedUnknown => "certificate_qualified_unknown",

    // Stage F: RFC 3161 signature timestamps.
    SignatureTimestampPresent => "signature_timestamp_present",
    SignatureTimestampAbsent => "signature_timestamp_absent",
    TimestampNotChecked => "timestamp_not_checked",
    TimestampTokenParsed => "timestamp_token_parsed",
    TimestampImprintOk => "timestamp_imprint_ok",
    TimestampImprintMismatch => "timestamp_imprint_mismatch",
    TimestampSignatureOk => "timestamp_signature_ok",
    TimestampSignatureInvalid => "timestamp_signature_invalid",
    TimestampTsaCertificateOk => "timestamp_tsa_certificate_ok",
    TimestampTsaCertificateInvalid => "timestamp_tsa_certificate_invalid",
    TimestampTsaPathOk => "timestamp_tsa_path_ok",
    TimestampTsaPathUntrusted => "timestamp_tsa_path_untrusted",
    TimestampTsaPathUnknown => "timestamp_tsa_path_unknown",
    TimestampBeforeSigningTime => "timestamp_before_signing_time",
    TimestampVerified => "timestamp_verified",
    ArchiveTimestampPresent => "archive_timestamp_present",

    // Dossier-level and document-level `es:TimeStamp` (M3).
    DossierTimestampVerified => "dossier_timestamp_verified",
    DossierTimestampInvalid => "dossier_timestamp_invalid",
    DossierTimestampNotChecked => "dossier_timestamp_not_checked",
    DocumentTimestampVerified => "document_timestamp_verified",
    DocumentTimestampInvalid => "document_timestamp_invalid",
    DocumentTimestampNotChecked => "document_timestamp_not_checked",
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

    /// A check that reports rather than decides. It never blocks a verdict.
    pub fn info(code: CheckCode, message: impl Into<String>) -> Self {
        Self::new(code, CheckStatus::Info, message)
    }
}

impl CheckCode {
    /// Whether this code reports a revocation answer.
    ///
    /// Revocation is folded into a verdict once, at the signature level, so a
    /// timestamp token's own summary must not fold it in a second time — and a
    /// token whose TSA's revocation status is merely *unknown* still proves
    /// when the signature existed.
    pub const fn is_revocation(self) -> bool {
        matches!(
            self,
            Self::RevocationPolicy
                | Self::RevocationNotChecked
                | Self::RevocationOk
                | Self::CertRevoked
                | Self::CertRevokedAfterValidationTime
                | Self::RevocationStatusUnknown
                | Self::RevocationStatusUnknownByResponder
                | Self::RevocationDataStale
                | Self::RevocationDataInvalid
                | Self::OcspResponderTrusted
                | Self::OnlineFetchFailed
        )
    }
}

/// Fold a list of checks into a verdict.
///
/// One `failed` makes the verdict `invalid`. Anything that is neither `passed`
/// nor `info` keeps it below `valid`. The function is monotone: adding a check
/// can only lower the verdict.
pub fn verdict_of(checks: &[Check]) -> Verdict {
    let mut verdict = Verdict::Valid;
    for check in checks {
        verdict = verdict.worst(match check.status {
            CheckStatus::Passed | CheckStatus::Info => Verdict::Valid,
            CheckStatus::Failed => Verdict::Invalid,
            CheckStatus::Skipped | CheckStatus::Unknown => Verdict::Indeterminate,
        });
    }
    verdict
}
