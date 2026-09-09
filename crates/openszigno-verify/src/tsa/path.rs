//! The TSA certificate's purpose and its certification path.
//!
//! RFC 3161 section 2.3 requires a critical `extendedKeyUsage` of exactly
//! `id-kp-timeStamping`, and the path is validated at the token's `genTime`,
//! since a timestamp asserts existence at that instant and the authority had
//! to be entitled to say so then.

use const_oid::ObjectIdentifier;

use crate::certs::{
    AnchorStatus, ChainEntry, OID_KP_TIME_STAMPING, ParsedCertificate, PathPurpose, dedup,
    validate_path_at,
};
use crate::codes::{Check, CheckCode, CheckStatus};
use crate::trust::UnixTime;

use super::TokenInput;

pub(super) const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// What the TSA path check leaves for the rest of token verification.
pub(super) struct TsaPath {
    /// The chain as it will be reported, still to be told about revocation.
    pub(super) chain: Vec<ChainEntry>,
    /// The validated path, leaf first and anchor last. Empty when none was
    /// built.
    pub(super) path: Vec<ParsedCertificate>,
    /// The untrusted certificates the path was built from.
    pub(super) candidates: Vec<ParsedCertificate>,
}

/// Check the TSA certificate's purpose and build its path at `gen_time`.
pub(super) fn check_tsa_certificate(
    tsa: &ParsedCertificate,
    certificates: &[ParsedCertificate],
    input: &TokenInput<'_>,
    status: AnchorStatus<'_>,
    gen_time: UnixTime,
    checks: &mut Vec<Check>,
) -> TsaPath {
    match timestamping_eku(tsa) {
        Ok(()) => checks.push(Check::passed(
            CheckCode::TimestampTsaCertificateOk,
            "the TSA certificate carries a critical id-kp-timeStamping extendedKeyUsage",
        )),
        Err(message) => {
            checks.push(Check::failed(
                CheckCode::TimestampTsaCertificateInvalid,
                message,
            ));
        }
    }

    let mut candidates = certificates.to_vec();
    candidates.extend(input.extra_certificates.iter().cloned());
    let candidates = dedup(candidates);
    // The validation time for the TSA's own chain is `genTime`: a
    // timestamp asserts existence at that instant, so that is when the TSA
    // had to be entitled to say so.
    let path = validate_path_at(
        tsa,
        &candidates,
        input.anchors,
        status,
        gen_time,
        input.limits,
        PathPurpose::TimeStamping,
    );
    let (code, status) = match path.code {
        CheckCode::CertPathOk => (CheckCode::TimestampTsaPathOk, CheckStatus::Passed),
        // No anchors, or a search that gave up: the tool does not know.
        CheckCode::CertPathUnknown | CheckCode::CertPathSearchExhausted => {
            (CheckCode::TimestampTsaPathUnknown, CheckStatus::Unknown)
        }
        // The path is sound but its anchor's TSA/QTST service was not granted
        // at the `genTime`. The list offers no trust for it then, which is a
        // gap rather than evidence against the token, so the code is reported
        // as it stands and blocks without condemning.
        CheckCode::TrustListServiceNotGranted => {
            (CheckCode::TrustListServiceNotGranted, CheckStatus::Unknown)
        }
        _ => (CheckCode::TimestampTsaPathUntrusted, CheckStatus::Failed),
    };
    checks.push(Check::new(code, status, path.message));
    checks.extend(path.advisories);
    TsaPath {
        chain: path.chain,
        path: path.path,
        candidates,
    }
}

/// RFC 3161 section 2.3: the TSA certificate must carry the
/// `extendedKeyUsage` extension, marked critical, with `id-kp-timeStamping`
/// and nothing else.
pub(super) fn timestamping_eku(certificate: &ParsedCertificate) -> Result<(), String> {
    let usages = certificate
        .extended_key_usages()
        .map_err(|()| "the TSA certificate's extendedKeyUsage is malformed".to_owned())?;
    let Some(usages) = usages else {
        return Err("the TSA certificate carries no extendedKeyUsage extension".to_owned());
    };
    if usages.as_slice() != [OID_KP_TIME_STAMPING] {
        return Err(
            "the TSA certificate's extendedKeyUsage is not exactly id-kp-timeStamping".to_owned(),
        );
    }
    if !certificate.is_critical(OID_EXT_KEY_USAGE) {
        return Err("the TSA certificate's extendedKeyUsage is not marked critical".to_owned());
    }
    Ok(())
}
