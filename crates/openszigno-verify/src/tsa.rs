//! Stage F: RFC 3161 timestamp tokens.
//!
//! A timestamp token is a CMS `SignedData` whose encapsulated content is a
//! `TSTInfo`. Verifying one means, in this order: parse it; recompute the
//! message imprint over the data the timestamp claims to cover and require
//! byte equality; verify the timestamp authority's `SignerInfo` signature over
//! the DER encoding of its signed attributes; require the TSA certificate to
//! carry a critical `extendedKeyUsage` of exactly `id-kp-timeStamping`; and
//! validate that certificate's path to a trust anchor **at `genTime`**, since
//! a timestamp asserts existence at that instant and the TSA must have been
//! entitled to say so then.
//!
//! The imprint step is the one that binds the token to this signature, and the
//! one most often skipped. Nothing here reports a token as verified unless
//! every one of those steps passed.

use const_oid::ObjectIdentifier;
use der::asn1::{GeneralizedTime, Int, OctetString};
use der::{Any, Decode, Encode, Sequence};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use x509_cert::attr::Attributes;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};

use crate::certs::{
    CertificateSource, CertificateSummary, ChainEntry, OID_KP_TIME_STAMPING, ParsedCertificate,
    PathPurpose, dedup, validate_path, verify_with_spki,
};
use crate::codes::{Check, CheckCode, CheckStatus};
use crate::policy::{Digest, SignatureScheme, VerifyLimits};
use crate::trust::{UnixTime, format_rfc3339};

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// The largest token this crate will parse, so an attacker-supplied
/// `EncapsulatedTimeStamp` cannot turn into unbounded work.
pub const MAX_TOKEN_BYTES: usize = 512 * 1024;

/// `MessageImprint`, RFC 3161 section 2.4.1.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub hashed_message: OctetString,
}

/// `Accuracy`, RFC 3161 section 2.4.2.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Accuracy {
    #[asn1(optional = "true")]
    pub seconds: Option<i32>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub millis: Option<i32>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub micros: Option<i32>,
}

/// `TSTInfo`, RFC 3161 section 2.4.2.
///
/// Hand-declared rather than pulled from another crate so that exactly what is
/// decoded, and what is refused, is visible here. `ordering` and `nonce` are
/// decoded as optional rather than defaulted: an absent `ordering` is the DER
/// encoding of `FALSE`, and neither field changes any decision this tool makes.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TstInfo {
    pub version: i32,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint,
    pub serial_number: SerialNumber,
    pub gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    pub accuracy: Option<Accuracy>,
    #[asn1(optional = "true")]
    pub ordering: Option<bool>,
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<x509_cert::ext::Extensions>,
}

/// `PKIStatusInfo`, RFC 3161 section 2.4.2 (from RFC 2510).
///
/// `statusString` and `failInfo` are decoded but not interpreted: only the
/// status itself decides whether the enclosed token may be looked at.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PkiStatusInfo {
    pub status: i32,
    #[asn1(optional = "true")]
    pub status_string: Option<Any>,
    #[asn1(optional = "true")]
    pub fail_info: Option<der::asn1::BitString>,
}

/// `TimeStampResp`, RFC 3161 section 2.4.2: the whole response a TSA returns,
/// of which the token is one field.
///
/// XAdES asks for the bare `TimeStampToken`, but producers of the 1.2.2 era
/// embedded the entire response in `xades:EncapsulatedTimeStamp`, and those
/// dossiers still have to verify.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampResp {
    pub status: PkiStatusInfo,
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<ContentInfo>,
}

/// `PKIStatus` values that mean a token was issued (RFC 3161 section 2.4.2).
const PKI_STATUS_GRANTED: i32 = 0;
const PKI_STATUS_GRANTED_WITH_MODS: i32 = 1;

/// What kind of timestamp a token was found as.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimestampKind {
    /// `xades:SignatureTimeStamp`, over the canonicalized `ds:SignatureValue`.
    SignatureTimestamp,
    /// A dossier-level `es:TimeStamp`, over the elements its `xades:Include`
    /// children name.
    DossierTimestamp,
    /// A document-level `es:TimeStamp`, over the elements its `xades:Include`
    /// children name.
    DocumentTimestamp,
}

/// One timestamp token in the machine-readable report.
#[derive(Clone, Debug, Serialize)]
pub struct TimestampReport {
    pub kind: TimestampKind,
    /// For a document-level `es:TimeStamp`, which document it belongs to.
    /// `null` for every other kind.
    pub document_index: Option<usize>,
    /// The `genTime` of the token, RFC 3339 UTC, or `null` when the token did
    /// not parse.
    pub gen_time: Option<String>,
    /// The declared accuracy in whole seconds, rounded up, or `null`.
    pub accuracy_seconds: Option<u64>,
    pub serial_hex: Option<String>,
    pub imprint_algorithm: Option<&'static str>,
    pub tsa_certificate: Option<CertificateSummary>,
    pub chain: Vec<ChainEntry>,
    /// True only when every check on this token passed, which is what allows
    /// its `gen_time` to become a validation time.
    pub verified: bool,
    pub checks: Vec<Check>,
}

/// Everything one token needs to be verified.
pub struct TokenInput<'a> {
    pub kind: TimestampKind,
    /// For a document-level `es:TimeStamp`, which document it belongs to.
    pub document_index: Option<usize>,
    /// The DER-encoded RFC 3161 token.
    pub token: Vec<u8>,
    /// The octets the imprint must be recomputed over: for a signature
    /// timestamp, the canonicalized `ds:SignatureValue` element.
    pub imprint_input: Vec<u8>,
    pub anchors: &'a [ParsedCertificate],
    /// Extra untrusted certificates offered for path building: the enclosing
    /// signature's `ds:KeyInfo` and `xades:CertificateValues` candidates, and
    /// the trust store's intermediates. Real dossiers carry the TSA's own
    /// issuing CA in the signature's `CertificateValues` rather than inside the
    /// token, so a token whose certificate set holds only the TSA leaf still
    /// chains. Anchors still come from the trust store alone.
    pub extra_certificates: &'a [ParsedCertificate],
    pub limits: &'a VerifyLimits,
    pub allow_legacy_algorithms: bool,
    /// The revocation material offered to the TSA's own chain. A timestamp
    /// signed by a revoked TSA certificate proves nothing.
    pub revocation: crate::revocation::RevocationData<'a>,
    pub revocation_policy: crate::trust::RevocationPolicy,
    /// The `xades:SigningTime` the signature claims, if any, for the ordering
    /// check.
    pub claimed_signing_time: Option<UnixTime>,
}

/// The outcome of verifying one token.
pub struct TokenOutcome {
    pub report: TimestampReport,
    /// The `genTime`, present whenever the token parsed. Only usable as a
    /// validation time when `report.verified` is true.
    pub gen_time: Option<UnixTime>,
}

impl TokenOutcome {
    fn failed(
        kind: TimestampKind,
        document_index: Option<usize>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            report: TimestampReport {
                kind,
                document_index,
                gen_time: None,
                accuracy_seconds: None,
                serial_hex: None,
                imprint_algorithm: None,
                tsa_certificate: None,
                chain: Vec::new(),
                verified: false,
                checks: vec![Check::failed(CheckCode::TimestampTokenParsed, message)],
            },
            gen_time: None,
        }
    }
}

/// Verify one RFC 3161 token against the data it claims to cover.
pub fn verify_token(input: &TokenInput<'_>) -> TokenOutcome {
    if input.token.len() > MAX_TOKEN_BYTES {
        return TokenOutcome::failed(
            input.kind,
            input.document_index,
            "the timestamp token is larger than this build will parse",
        );
    }
    let content = match content_info(&input.token) {
        Ok(content) => content,
        Err(message) => return TokenOutcome::failed(input.kind, input.document_index, message),
    };
    if content.content_type != OID_SIGNED_DATA {
        return TokenOutcome::failed(
            input.kind,
            input.document_index,
            "the timestamp token is not a CMS SignedData",
        );
    }
    let signed_data = content
        .content
        .to_der()
        .ok()
        .and_then(|der| SignedData::from_der(&der).ok());
    let Some(signed_data) = signed_data else {
        return TokenOutcome::failed(
            input.kind,
            input.document_index,
            "the timestamp token's SignedData could not be decoded",
        );
    };
    if signed_data.encap_content_info.econtent_type != OID_CT_TST_INFO {
        return TokenOutcome::failed(
            input.kind,
            input.document_index,
            "the timestamp token does not encapsulate an id-ct-TSTInfo content",
        );
    }
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .and_then(|content| content.decode_as::<OctetString>().ok());
    let Some(econtent) = econtent else {
        return TokenOutcome::failed(
            input.kind,
            input.document_index,
            "the timestamp token carries no eContent",
        );
    };
    let Ok(tst_info) = TstInfo::from_der(econtent.as_bytes()) else {
        return TokenOutcome::failed(
            input.kind,
            input.document_index,
            "the encapsulated TSTInfo could not be decoded",
        );
    };

    let mut checks = vec![Check::passed(
        CheckCode::TimestampTokenParsed,
        "the token parsed as CMS SignedData over an RFC 3161 TSTInfo",
    )];
    let gen_time = tst_info.gen_time.to_unix_duration().as_secs() as UnixTime;
    let accuracy_seconds = tst_info.accuracy.as_ref().map(accuracy_seconds);

    // --- The imprint, which is what binds the token to this signature -------
    let imprint_algorithm = digest_of_oid(
        &tst_info.message_imprint.hash_algorithm.oid,
        input.allow_legacy_algorithms,
    );
    match imprint_algorithm {
        None => checks.push(Check::failed(
            CheckCode::TimestampImprintMismatch,
            "the message imprint names a digest algorithm outside the pinned allowlist",
        )),
        Some(algorithm) => {
            let computed = digest(algorithm, &input.imprint_input);
            if computed == tst_info.message_imprint.hashed_message.as_bytes() {
                checks.push(Check::passed(
                    CheckCode::TimestampImprintOk,
                    "the message imprint matches the data the timestamp covers",
                ));
            } else {
                checks.push(Check::failed(
                    CheckCode::TimestampImprintMismatch,
                    "the message imprint does not match the data the timestamp covers",
                ));
            }
        }
    }

    // --- The TSA signature over the signed attributes -----------------------
    let certificates: Vec<ParsedCertificate> = signed_data
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .iter()
                .filter_map(|choice| match choice {
                    CertificateChoices::Certificate(certificate) => {
                        certificate.to_der().ok().and_then(|der| {
                            ParsedCertificate::from_der(&der, CertificateSource::TimestampToken)
                        })
                    }
                    CertificateChoices::Other(_) => None,
                })
                .take(input.limits.max_certificates)
                .collect()
        })
        .unwrap_or_default();

    let signer_info = single_signer(&signed_data);
    let tsa = signer_info.and_then(|info| find_signer_certificate(info, &certificates));
    match (signer_info, tsa) {
        (Some(info), Some(tsa)) => {
            match verify_signer_info(
                info,
                tsa,
                econtent.as_bytes(),
                input.allow_legacy_algorithms,
            ) {
                Ok(()) => checks.push(Check::passed(
                    CheckCode::TimestampSignatureOk,
                    "the timestamp authority's signature over the signed attributes verified",
                )),
                Err(message) => {
                    checks.push(Check::failed(CheckCode::TimestampSignatureInvalid, message));
                }
            }
        }
        (Some(_), None) => checks.push(Check::failed(
            CheckCode::TimestampSignatureInvalid,
            "the token's certificate set holds no certificate matching its SignerInfo",
        )),
        (None, _) => checks.push(Check::failed(
            CheckCode::TimestampSignatureInvalid,
            "the token does not carry exactly one SignerInfo",
        )),
    }

    // --- The TSA certificate and its path -----------------------------------
    if let Some(tsa) = tsa {
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

        let mut candidates = certificates.clone();
        candidates.extend(input.extra_certificates.iter().cloned());
        let candidates = dedup(candidates);
        // The validation time for the TSA's own chain is `genTime`: a
        // timestamp asserts existence at that instant, so that is when the TSA
        // had to be entitled to say so.
        let path = validate_path(
            tsa,
            &candidates,
            input.anchors,
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
            _ => (CheckCode::TimestampTsaPathUntrusted, CheckStatus::Failed),
        };
        checks.push(Check::new(code, status, path.message));
        checks.extend(path.advisories);

        // --- The TSA chain's revocation -------------------------------------
        // Checked at `genTime`, the same instant the chain itself is validated
        // at: the question is whether the authority was entitled to speak when
        // it spoke.
        let mut chain = path.chain;
        if !path.path.is_empty() {
            let outcome = crate::revocation::check_path(&crate::revocation::PathRevocationInput {
                path: &path.path,
                candidates: &candidates,
                data: &input.revocation,
                time: gen_time,
                // The instant a TSA's own chain is validated at is the
                // `genTime` the token asserts, so it cannot also be the proof
                // that dismisses a revocation dated after it. A TSA
                // certificate revoked after its own genTime stays `unknown`.
                time_is_proven: false,
                policy: input.revocation_policy,
                role: crate::revocation::ChainRole::TimestampAuthority,
                limits: input.limits,
            });
            for (entry, status) in chain.iter_mut().zip(outcome.per_certificate) {
                entry.revocation = Some(status);
            }
            checks.push(outcome.check);
        }

        // --- Ordering against the claimed signing time ----------------------
        if let Some(claimed) = input.claimed_signing_time {
            let slack = i64::try_from(accuracy_seconds.unwrap_or(0)).unwrap_or(i64::MAX);
            if gen_time < claimed.saturating_sub(slack) {
                checks.push(Check::unknown(
                    CheckCode::TimestampBeforeSigningTime,
                    "the token's genTime is earlier than the claimed xades:SigningTime by more than the declared accuracy; the claim is unauthenticated, so this is reported rather than treated as a failure",
                ));
            }
        }

        let verified = token_verified(&checks);
        return TokenOutcome {
            report: TimestampReport {
                kind: input.kind,
                document_index: input.document_index,
                gen_time: Some(format_rfc3339(gen_time)),
                accuracy_seconds,
                serial_hex: Some(hex(tst_info.serial_number.as_bytes())),
                imprint_algorithm: imprint_algorithm.map(Digest::as_str),
                tsa_certificate: Some(tsa.summary()),
                chain,
                verified,
                checks,
            },
            gen_time: Some(gen_time),
        };
    }

    TokenOutcome {
        report: TimestampReport {
            kind: input.kind,
            document_index: input.document_index,
            gen_time: Some(format_rfc3339(gen_time)),
            accuracy_seconds,
            serial_hex: Some(hex(tst_info.serial_number.as_bytes())),
            imprint_algorithm: imprint_algorithm.map(Digest::as_str),
            tsa_certificate: None,
            chain: Vec::new(),
            verified: false,
            checks,
        },
        gen_time: Some(gen_time),
    }
}

/// The `ContentInfo` inside an `xades:EncapsulatedTimeStamp`.
///
/// XAdES prescribes a bare RFC 3161 `TimeStampToken`, which is a CMS
/// `ContentInfo`. Older producers embedded the whole `TimeStampResp` instead,
/// so that shape is accepted too — but only after its `PKIStatus` says a token
/// was actually issued: a response that reports a rejection carries no
/// timestamp to believe, and reading its token field anyway would turn a
/// refusal into a verification.
/// Every certificate carried inside one RFC 3161 token, as DER.
///
/// A caller that needs to know *which* certificates a dossier's revocation
/// answers would have to cover has to look inside the tokens too: a TSA's own
/// leaf certificate usually travels nowhere else. Nothing here is trusted or
/// even validated — these are candidates, exactly as they are everywhere else.
pub fn token_certificates(der: &[u8]) -> Vec<Vec<u8>> {
    if der.len() > MAX_TOKEN_BYTES {
        return Vec::new();
    }
    let Ok(content) = content_info(der) else {
        return Vec::new();
    };
    let signed_data = content
        .content
        .to_der()
        .ok()
        .and_then(|der| SignedData::from_der(&der).ok());
    let Some(signed_data) = signed_data else {
        return Vec::new();
    };
    let Some(set) = signed_data.certificates else {
        return Vec::new();
    };
    set.0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => certificate.to_der().ok(),
            CertificateChoices::Other(_) => None,
        })
        .collect()
}

fn content_info(der: &[u8]) -> Result<ContentInfo, String> {
    if let Ok(content) = ContentInfo::from_der(der) {
        return Ok(content);
    }
    let Ok(response) = TimeStampResp::from_der(der) else {
        return Err(format!(
            "the timestamp is neither a CMS ContentInfo nor an RFC 3161 TimeStampResp; its outermost DER tag is {}",
            outer_tag(der)
        ));
    };
    match response.status.status {
        PKI_STATUS_GRANTED | PKI_STATUS_GRANTED_WITH_MODS => {}
        status => {
            return Err(format!(
                "the RFC 3161 response reports PKIStatus {status}, which is neither granted nor grantedWithMods"
            ));
        }
    }
    response
        .time_stamp_token
        .ok_or_else(|| "the RFC 3161 response carries no timestamp token".to_owned())
}

/// The outermost DER tag, named where this build knows the name. The tag of
/// attacker-supplied bytes is public information and is the one thing that
/// makes "this did not parse" actionable.
fn outer_tag(der: &[u8]) -> String {
    let Some(byte) = der.first() else {
        return "absent (the input is empty)".to_owned();
    };
    let name = match byte {
        0x02 => " (INTEGER)",
        0x03 => " (BIT STRING)",
        0x04 => " (OCTET STRING)",
        0x05 => " (NULL)",
        0x06 => " (OBJECT IDENTIFIER)",
        0x0c => " (UTF8String)",
        0x30 => " (SEQUENCE)",
        0x31 => " (SET)",
        _ => "",
    };
    format!("0x{byte:02x}{name}")
}

/// The one check that summarises a token, so a signature's own check list says
/// what became of each of its timestamps without repeating the detail.
///
/// **This check is never `failed`.** A timestamp that does not verify — for any
/// reason, from a malformed token to a TSA chain that reaches no anchor —
/// supplies no proof that the signature existed at a given time. It says
/// nothing about the signature itself, so under ETSI EN 319 102-1 it yields
/// INDETERMINATE rather than TOTAL-FAILED: the missing proof is missing
/// information, not evidence of forgery. The token keeps its own `failed`
/// checks and `verified: false`, and the validation time falls back to `--at`
/// or the clock.
/// Whether a token may move the validation time.
///
/// Stricter than `passed` in one direction and looser in another, on purpose:
/// a `failed` check anywhere sinks the token, but a revocation answer the tool
/// could not obtain does not. An unobtainable revocation status still blocks
/// the *signature's* verdict through [`summary_check`]; what it must not do is
/// silently move the validation time back to "now", which would make an
/// expired signing certificate look expired for a second, unrelated reason.
fn token_verified(checks: &[Check]) -> bool {
    checks.iter().all(|check| match check.status {
        CheckStatus::Passed | CheckStatus::Info => true,
        CheckStatus::Failed => false,
        CheckStatus::Unknown | CheckStatus::Skipped => check.code.is_revocation(),
    })
}

/// The token's own revocation check, so the caller can fold it into the
/// signature's verdict exactly once.
pub fn revocation_check(checks: &[Check]) -> Option<&Check> {
    checks.iter().find(|check| check.code.is_revocation())
}

pub fn summary_check(checks: &[Check]) -> Check {
    // Revocation is excluded here and folded in separately: a TSA certificate
    // whose revocation status could not be obtained still binds the signature
    // to a time, and saying otherwise would quietly move the validation time
    // back to "now" for a reason that has nothing to do with the timestamp.
    let checks: Vec<&Check> = checks
        .iter()
        .filter(|check| !check.code.is_revocation())
        .collect();
    if checks
        .iter()
        .all(|check| matches!(check.status, CheckStatus::Passed | CheckStatus::Info))
    {
        return Check::passed(
            CheckCode::TimestampVerified,
            "the timestamp token verified against a configured trust anchor",
        );
    }
    if checks
        .iter()
        .any(|check| check.status == CheckStatus::Failed)
    {
        return Check::unknown(
            CheckCode::TimestampVerified,
            "the timestamp token did not verify, so it proves nothing about when this signature existed; see the token's own checks",
        );
    }
    Check::unknown(
        CheckCode::TimestampVerified,
        "the timestamp token could not be fully verified; see the token's own checks",
    )
}

fn accuracy_seconds(accuracy: &Accuracy) -> u64 {
    let seconds = u64::try_from(accuracy.seconds.unwrap_or(0)).unwrap_or(0);
    let millis = u64::try_from(accuracy.millis.unwrap_or(0)).unwrap_or(0);
    let micros = u64::try_from(accuracy.micros.unwrap_or(0)).unwrap_or(0);
    // Sub-second accuracy still widens the window by up to a second once the
    // comparison is made in whole seconds, so it is rounded up.
    seconds + u64::from(millis > 0 || micros > 0)
}

fn single_signer(signed_data: &SignedData) -> Option<&SignerInfo> {
    let mut signers = signed_data.signer_infos.0.iter();
    let first = signers.next()?;
    signers.next().is_none().then_some(first)
}

/// The certificate the `SignerInfo` names, by issuer and serial or by subject
/// key identifier. Nothing is guessed: a token whose `sid` matches nothing in
/// its own certificate set is rejected rather than verified against whatever
/// certificate happens to be present.
fn find_signer_certificate<'a>(
    signer: &SignerInfo,
    certificates: &'a [ParsedCertificate],
) -> Option<&'a ParsedCertificate> {
    match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(identifier) => {
            let issuer = identifier.issuer.to_der().ok()?;
            certificates.iter().find(|candidate| {
                candidate.issuer_der() == issuer
                    && candidate
                        .certificate
                        .tbs_certificate
                        .serial_number
                        .as_bytes()
                        == identifier.serial_number.as_bytes()
            })
        }
        SignerIdentifier::SubjectKeyIdentifier(identifier) => {
            let wanted = identifier.0.as_bytes();
            certificates
                .iter()
                .find(|candidate| subject_key_identifier(candidate).as_deref() == Some(wanted))
        }
    }
}

fn subject_key_identifier(certificate: &ParsedCertificate) -> Option<Vec<u8>> {
    let extensions = certificate
        .certificate
        .tbs_certificate
        .extensions
        .as_ref()?;
    let extension = extensions
        .iter()
        .find(|extension| extension.extn_id == OID_SUBJECT_KEY_IDENTIFIER)?;
    OctetString::from_der(extension.extn_value.as_bytes())
        .ok()
        .map(|value| value.as_bytes().to_vec())
}

/// RFC 5652 section 5.4 and RFC 3161 section 2.4.2, in order: the signed
/// attributes must exist, must name the encapsulated content type, must carry
/// a message digest equal to the digest of the eContent, and the signature
/// must verify over the DER `SET OF` encoding of those attributes.
fn verify_signer_info(
    signer: &SignerInfo,
    certificate: &ParsedCertificate,
    econtent: &[u8],
    allow_legacy_algorithms: bool,
) -> Result<(), String> {
    let Some(attributes) = signer.signed_attrs.as_ref() else {
        return Err("the SignerInfo carries no signed attributes".to_owned());
    };
    let Some(digest_algorithm) = digest_of_oid(&signer.digest_alg.oid, allow_legacy_algorithms)
    else {
        return Err(
            "the SignerInfo names a digest algorithm outside the pinned allowlist".to_owned(),
        );
    };

    let content_type = attribute_value(attributes, OID_CONTENT_TYPE)
        .and_then(|value| value.decode_as::<ObjectIdentifier>().ok());
    match content_type {
        Some(oid) if oid == OID_CT_TST_INFO => {}
        Some(_) => return Err("the signed content-type attribute is not id-ct-TSTInfo".to_owned()),
        None => return Err("the signed attributes carry no usable content-type".to_owned()),
    }

    let message_digest = attribute_value(attributes, OID_MESSAGE_DIGEST)
        .and_then(|value| value.decode_as::<OctetString>().ok());
    let Some(message_digest) = message_digest else {
        return Err("the signed attributes carry no usable message-digest".to_owned());
    };
    if message_digest.as_bytes() != digest(digest_algorithm, econtent) {
        return Err("the signed message-digest attribute does not match the eContent".to_owned());
    }

    let scheme =
        signature_scheme(&signer.signature_algorithm.oid, digest_algorithm).ok_or_else(|| {
            "the SignerInfo signature algorithm is outside the pinned allowlist".to_owned()
        })?;
    // RFC 5652: the signature is computed over the DER encoding of the signed
    // attributes with the `SET OF` tag, not over the `[0] IMPLICIT` form that
    // appears in the message.
    let message = attributes
        .to_der()
        .map_err(|_| "the signed attributes could not be re-encoded".to_owned())?;
    verify_with_spki(
        &certificate.certificate,
        scheme,
        &message,
        signer.signature.as_bytes(),
        true,
    )
    .map_err(|_| "the signature over the signed attributes did not verify".to_owned())
}

fn attribute_value(attributes: &Attributes, oid: ObjectIdentifier) -> Option<&Any> {
    attributes
        .iter()
        .find(|attribute| attribute.oid == oid)
        .and_then(|attribute| attribute.values.iter().next())
}

/// RFC 3161 section 2.3: the TSA certificate must carry the
/// `extendedKeyUsage` extension, marked critical, with `id-kp-timeStamping`
/// and nothing else.
fn timestamping_eku(certificate: &ParsedCertificate) -> Result<(), String> {
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

fn digest_of_oid(oid: &ObjectIdentifier, allow_legacy_algorithms: bool) -> Option<Digest> {
    let digest = match *oid {
        OID_SHA1 => Digest::Sha1,
        OID_SHA256 => Digest::Sha256,
        OID_SHA384 => Digest::Sha384,
        OID_SHA512 => Digest::Sha512,
        _ => return None,
    };
    (!digest.is_legacy() || allow_legacy_algorithms).then_some(digest)
}

fn signature_scheme(oid: &ObjectIdentifier, digest: Digest) -> Option<SignatureScheme> {
    Some(match *oid {
        // A bare `rsaEncryption` means "PKCS#1 v1.5 with the digest the
        // SignerInfo already named", which is what most TSAs emit.
        OID_RSA_ENCRYPTION => SignatureScheme::RsaPkcs1(digest),
        OID_SHA256_RSA => SignatureScheme::RsaPkcs1(Digest::Sha256),
        OID_SHA384_RSA => SignatureScheme::RsaPkcs1(Digest::Sha384),
        OID_SHA512_RSA => SignatureScheme::RsaPkcs1(Digest::Sha512),
        OID_ECDSA_SHA256 => SignatureScheme::Ecdsa(Digest::Sha256),
        OID_ECDSA_SHA384 => SignatureScheme::Ecdsa(Digest::Sha384),
        _ => return None,
    })
}

fn digest(algorithm: Digest, bytes: &[u8]) -> Vec<u8> {
    match algorithm {
        Digest::Sha1 => Sha1::digest(bytes).to_vec(),
        Digest::Sha256 => Sha256::digest(bytes).to_vec(),
        Digest::Sha384 => Sha384::digest(bytes).to_vec(),
        Digest::Sha512 => Sha512::digest(bytes).to_vec(),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

#[cfg(test)]
mod tests {
    //! White-box tests for the refusal paths.
    //!
    //! Every token here is malformed on purpose and is built in-test, so the
    //! branches that reject a token are exercised without needing a working
    //! timestamp authority. The end-to-end positive cases live in
    //! `tests/timestamps.rs`.

    use super::*;
    use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
    use cms::content_info::CmsVersion;
    use cms::signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignerInfo as CmsSignerInfo, SignerInfos,
    };
    use der::Tag;
    use der::asn1::SetOfVec;
    use x509_cert::attr::{Attribute, Attributes};

    fn oid(text: &str) -> ObjectIdentifier {
        text.parse().expect("a valid OID")
    }

    fn sha256_algorithm() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: OID_SHA256,
            parameters: None,
        }
    }

    /// A self-signed certificate over a freshly generated P-256 key, which is
    /// all these tests need: none of them reaches a signature check that has to
    /// succeed.
    fn certificate() -> x509_cert::Certificate {
        certificate_with_key_identifier(None)
    }

    /// A self-signed certificate, optionally carrying the given
    /// `subjectKeyIdentifier`.
    fn certificate_with_key_identifier(identifier: Option<&[u8]>) -> x509_cert::Certificate {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("a P-256 key is generated");
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("no SAN is valid");
        if let Some(identifier) = identifier {
            params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 14],
                OctetString::new(identifier.to_vec())
                    .expect("encodes")
                    .to_der()
                    .expect("encodes"),
            )];
        }
        let certificate = params.self_signed(&key).expect("self-signing succeeds");
        x509_cert::Certificate::from_der(certificate.der()).expect("the certificate parses")
    }

    fn tst_info(imprint_oid: ObjectIdentifier) -> Vec<u8> {
        TstInfo {
            version: 1,
            policy: oid("1.3.6.1.4.1.99999.1"),
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifierOwned {
                    oid: imprint_oid,
                    parameters: None,
                },
                hashed_message: OctetString::new(vec![0u8; 32]).expect("encodes"),
            },
            serial_number: SerialNumber::new(&[1]).expect("encodes"),
            gen_time: GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
                1_590_000_000,
            ))
            .expect("encodes"),
            accuracy: Some(Accuracy {
                seconds: None,
                millis: Some(500),
                micros: None,
            }),
            ordering: None,
            nonce: None,
            tsa: None,
            extensions: None,
        }
        .to_der()
        .expect("the TSTInfo encodes")
    }

    /// A token wrapping `content` as the `SignedData`'s encapsulated content.
    fn token(
        econtent_type: ObjectIdentifier,
        econtent: Option<Any>,
        signers: Vec<CmsSignerInfo>,
        certificates: Vec<x509_cert::Certificate>,
    ) -> Vec<u8> {
        let signed_data = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::try_from(vec![sha256_algorithm()]).expect("encodes"),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type,
                econtent,
            },
            certificates: (!certificates.is_empty()).then(|| {
                CertificateSet(
                    SetOfVec::try_from(
                        certificates
                            .into_iter()
                            .map(CertificateChoices::Certificate)
                            .collect::<Vec<_>>(),
                    )
                    .expect("encodes"),
                )
            }),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(signers).expect("encodes")),
        };
        ContentInfo {
            content_type: OID_SIGNED_DATA,
            content: Any::encode_from(&signed_data).expect("encodes"),
        }
        .to_der()
        .expect("encodes")
    }

    fn attributes(pairs: Vec<(ObjectIdentifier, Any)>) -> Attributes {
        SetOfVec::try_from(
            pairs
                .into_iter()
                .map(|(oid, value)| Attribute {
                    oid,
                    values: SetOfVec::try_from(vec![value]).expect("one value"),
                })
                .collect::<Vec<_>>(),
        )
        .expect("the attributes encode")
    }

    fn signer(
        certificate: &x509_cert::Certificate,
        signed_attrs: Option<Attributes>,
        signature_algorithm: ObjectIdentifier,
    ) -> CmsSignerInfo {
        CmsSignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: certificate.tbs_certificate.issuer.clone(),
                serial_number: certificate.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: sha256_algorithm(),
            signed_attrs,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: signature_algorithm,
                parameters: None,
            },
            signature: OctetString::new(vec![0u8; 32]).expect("encodes"),
            unsigned_attrs: None,
        }
    }

    /// Verify `bytes` with an empty trust store, and return the codes emitted.
    fn outcome(bytes: Vec<u8>) -> TokenOutcome {
        let limits = VerifyLimits::default();
        verify_token(&TokenInput {
            document_index: None,
            kind: TimestampKind::SignatureTimestamp,
            token: bytes,
            imprint_input: b"data".to_vec(),
            anchors: &[],
            extra_certificates: &[],
            limits: &limits,
            allow_legacy_algorithms: false,
            revocation: crate::revocation::RevocationData::default(),
            revocation_policy: crate::trust::RevocationPolicy::Offline,
            claimed_signing_time: None,
        })
    }

    fn codes(outcome: &TokenOutcome) -> Vec<(&'static str, &'static str)> {
        outcome
            .report
            .checks
            .iter()
            .map(|check| (check.code.as_str(), check.status.as_str()))
            .collect()
    }

    #[test]
    fn an_oversized_token_is_refused_before_parsing() {
        let outcome = outcome(vec![0u8; MAX_TOKEN_BYTES + 1]);
        assert_eq!(codes(&outcome), vec![("timestamp_token_parsed", "failed")]);
    }

    #[test]
    fn bytes_that_are_not_a_content_info_are_refused() {
        for bytes in [Vec::new(), vec![0xff; 8], vec![0x30, 0x00]] {
            let outcome = outcome(bytes);
            assert_eq!(codes(&outcome), vec![("timestamp_token_parsed", "failed")]);
            assert_eq!(outcome.gen_time, None);
        }
    }

    #[test]
    fn a_content_info_that_is_not_signed_data_is_refused() {
        let bytes = ContentInfo {
            content_type: oid("1.2.840.113549.1.7.1"),
            content: Any::new(Tag::OctetString, vec![1, 2, 3]).expect("encodes"),
        }
        .to_der()
        .expect("encodes");
        assert_eq!(
            codes(&outcome(bytes)),
            vec![("timestamp_token_parsed", "failed")]
        );
    }

    #[test]
    fn a_signed_data_that_does_not_decode_is_refused() {
        let bytes = ContentInfo {
            content_type: OID_SIGNED_DATA,
            content: Any::new(Tag::OctetString, vec![1, 2, 3]).expect("encodes"),
        }
        .to_der()
        .expect("encodes");
        assert_eq!(
            codes(&outcome(bytes)),
            vec![("timestamp_token_parsed", "failed")]
        );
    }

    #[test]
    fn a_token_over_another_content_type_is_refused() {
        let bytes = token(oid("1.2.840.113549.1.7.1"), None, Vec::new(), Vec::new());
        assert_eq!(
            codes(&outcome(bytes)),
            vec![("timestamp_token_parsed", "failed")]
        );
    }

    #[test]
    fn a_token_without_econtent_is_refused() {
        let bytes = token(OID_CT_TST_INFO, None, Vec::new(), Vec::new());
        assert_eq!(
            codes(&outcome(bytes)),
            vec![("timestamp_token_parsed", "failed")]
        );
    }

    #[test]
    fn an_econtent_that_is_not_a_tst_info_is_refused() {
        let bytes = token(
            OID_CT_TST_INFO,
            Some(Any::new(Tag::OctetString, vec![1, 2, 3]).expect("encodes")),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            codes(&outcome(bytes)),
            vec![("timestamp_token_parsed", "failed")]
        );
    }

    /// A parsed token with no `SignerInfo` still reports its `genTime`, and
    /// still fails: nothing signed it.
    #[test]
    fn a_token_without_a_signer_info_fails_the_signature() {
        let bytes = token(
            OID_CT_TST_INFO,
            Some(Any::new(Tag::OctetString, tst_info(OID_SHA256)).expect("encodes")),
            Vec::new(),
            Vec::new(),
        );
        let outcome = outcome(bytes);
        assert!(codes(&outcome).contains(&("timestamp_signature_invalid", "failed")));
        assert!(!outcome.report.verified);
        assert!(outcome.report.gen_time.is_some());
        // Sub-second accuracy widens the window to a whole second.
        assert_eq!(outcome.report.accuracy_seconds, Some(1));
        // The token's own checks stay `failed`; the check the signature sees
        // is `unknown`, because a token that did not verify proves nothing
        // either way about the signature.
        assert_eq!(
            summary_check(&outcome.report.checks).status,
            CheckStatus::Unknown
        );
    }

    #[test]
    fn an_imprint_algorithm_outside_the_allowlist_fails() {
        let bytes = token(
            OID_CT_TST_INFO,
            Some(Any::new(Tag::OctetString, tst_info(oid("1.2.840.113549.2.5"))).expect("encodes")),
            Vec::new(),
            Vec::new(),
        );
        let outcome = outcome(bytes);
        assert!(codes(&outcome).contains(&("timestamp_imprint_mismatch", "failed")));
        assert_eq!(outcome.report.imprint_algorithm, None);
    }

    #[test]
    fn a_signer_info_naming_no_carried_certificate_fails() {
        let certificate = certificate();
        let bytes = token(
            OID_CT_TST_INFO,
            Some(Any::new(Tag::OctetString, tst_info(OID_SHA256)).expect("encodes")),
            vec![signer(&certificate, None, OID_RSA_ENCRYPTION)],
            Vec::new(),
        );
        let outcome = outcome(bytes);
        assert!(codes(&outcome).contains(&("timestamp_signature_invalid", "failed")));
        assert!(outcome.report.tsa_certificate.is_none());
    }

    /// The signed attributes are mandatory, and each of the ways they can be
    /// wrong is refused rather than waved through.
    #[test]
    fn every_shape_of_bad_signed_attributes_fails() {
        let certificate = certificate();
        let content_type = |value: ObjectIdentifier| {
            (OID_CONTENT_TYPE, Any::encode_from(&value).expect("encodes"))
        };
        let digest = |bytes: Vec<u8>| {
            (
                OID_MESSAGE_DIGEST,
                Any::encode_from(&OctetString::new(bytes).expect("encodes")).expect("encodes"),
            )
        };
        let cases: Vec<Option<Attributes>> = vec![
            // No signed attributes at all.
            None,
            // A content type that is not id-ct-TSTInfo.
            Some(attributes(vec![
                content_type(oid("1.2.840.113549.1.7.1")),
                digest(vec![0u8; 32]),
            ])),
            // No content type.
            Some(attributes(vec![digest(vec![0u8; 32])])),
            // No message digest.
            Some(attributes(vec![content_type(OID_CT_TST_INFO)])),
            // A message digest over something else.
            Some(attributes(vec![
                content_type(OID_CT_TST_INFO),
                digest(vec![9u8; 32]),
            ])),
        ];
        for signed_attrs in cases {
            let bytes = token(
                OID_CT_TST_INFO,
                Some(Any::new(Tag::OctetString, tst_info(OID_SHA256)).expect("encodes")),
                vec![signer(&certificate, signed_attrs, OID_RSA_ENCRYPTION)],
                vec![certificate.clone()],
            );
            let outcome = outcome(bytes);
            assert!(
                codes(&outcome).contains(&("timestamp_signature_invalid", "failed")),
                "expected a signature failure; got {:?}",
                codes(&outcome)
            );
            // The TSA certificate was located, so the certificate checks ran.
            assert!(codes(&outcome).contains(&("timestamp_tsa_certificate_invalid", "failed")));
            // With no anchors configured the path is unknown, never untrusted.
            assert!(codes(&outcome).contains(&("timestamp_tsa_path_unknown", "unknown")));
        }
    }

    #[test]
    fn a_signature_algorithm_outside_the_allowlist_fails() {
        let certificate = certificate();
        let econtent = tst_info(OID_SHA256);
        let signed_attrs = attributes(vec![
            (
                OID_CONTENT_TYPE,
                Any::encode_from(&OID_CT_TST_INFO).expect("encodes"),
            ),
            (
                OID_MESSAGE_DIGEST,
                Any::encode_from(
                    &OctetString::new(Sha256::digest(&econtent).to_vec()).expect("encodes"),
                )
                .expect("encodes"),
            ),
        ]);
        let bytes = token(
            OID_CT_TST_INFO,
            Some(Any::new(Tag::OctetString, econtent).expect("encodes")),
            vec![signer(
                &certificate,
                Some(signed_attrs),
                // ecdsa-with-SHA512, which this build does not implement.
                oid("1.2.840.10045.4.3.4"),
            )],
            vec![certificate.clone()],
        );
        assert!(codes(&outcome(bytes)).contains(&("timestamp_signature_invalid", "failed")));
    }

    /// More than one `SignerInfo` is a shape this build does not process, and
    /// picking one of them would be a guess.
    #[test]
    fn more_than_one_signer_info_fails() {
        let first = certificate();
        let second = certificate();
        let bytes = token(
            OID_CT_TST_INFO,
            Some(Any::new(Tag::OctetString, tst_info(OID_SHA256)).expect("encodes")),
            vec![
                signer(&first, None, OID_RSA_ENCRYPTION),
                signer(&second, None, OID_RSA_ENCRYPTION),
            ],
            vec![first, second],
        );
        assert!(codes(&outcome(bytes)).contains(&("timestamp_signature_invalid", "failed")));
    }

    /// A `SignerInfo` may name its certificate by subject key identifier, and
    /// an identifier that matches nothing must not fall back to a guess.
    #[test]
    fn a_subject_key_identifier_selects_or_rejects() {
        let identifier = vec![7u8; 20];
        let certificate = certificate_with_key_identifier(Some(&identifier));
        assert_eq!(
            subject_key_identifier(
                &ParsedCertificate::from_der(
                    &certificate.to_der().expect("encodes"),
                    CertificateSource::TimestampToken,
                )
                .expect("parses"),
            ),
            Some(identifier.clone())
        );

        for (bytes, expect_certificate) in [(identifier.clone(), true), (vec![0u8; 20], false)] {
            let mut info = signer(&certificate, None, OID_RSA_ENCRYPTION);
            info.sid =
                SignerIdentifier::SubjectKeyIdentifier(x509_cert::ext::pkix::SubjectKeyIdentifier(
                    OctetString::new(bytes).expect("encodes"),
                ));
            let token = token(
                OID_CT_TST_INFO,
                Some(Any::new(Tag::OctetString, tst_info(OID_SHA256)).expect("encodes")),
                vec![info],
                vec![certificate.clone()],
            );
            let outcome = outcome(token);
            assert_eq!(outcome.report.tsa_certificate.is_some(), expect_certificate);
            assert!(codes(&outcome).contains(&("timestamp_signature_invalid", "failed")));
        }
    }

    #[test]
    fn the_algorithm_maps_are_pinned() {
        assert_eq!(digest_of_oid(&OID_SHA384, false), Some(Digest::Sha384));
        assert_eq!(digest_of_oid(&OID_SHA512, false), Some(Digest::Sha512));
        // SHA-1 is admitted only for diagnosis, never by default.
        assert_eq!(digest_of_oid(&OID_SHA1, false), None);
        assert_eq!(digest_of_oid(&OID_SHA1, true), Some(Digest::Sha1));
        assert_eq!(digest_of_oid(&oid("1.2.840.113549.2.5"), true), None);

        assert_eq!(
            signature_scheme(&OID_SHA384_RSA, Digest::Sha256),
            Some(SignatureScheme::RsaPkcs1(Digest::Sha384))
        );
        assert_eq!(
            signature_scheme(&OID_SHA512_RSA, Digest::Sha256),
            Some(SignatureScheme::RsaPkcs1(Digest::Sha512))
        );
        assert_eq!(
            signature_scheme(&OID_ECDSA_SHA256, Digest::Sha256),
            Some(SignatureScheme::Ecdsa(Digest::Sha256))
        );
        assert_eq!(
            signature_scheme(&OID_ECDSA_SHA384, Digest::Sha256),
            Some(SignatureScheme::Ecdsa(Digest::Sha384))
        );
        // RSASSA-PSS needs its parameters read, which this build does not do.
        assert_eq!(
            signature_scheme(&oid("1.2.840.113549.1.1.10"), Digest::Sha256),
            None
        );
    }

    #[test]
    fn accuracy_is_rounded_up_to_whole_seconds() {
        let accuracy = |seconds, millis, micros| {
            accuracy_seconds(&Accuracy {
                seconds,
                millis,
                micros,
            })
        };
        assert_eq!(accuracy(None, None, None), 0);
        assert_eq!(accuracy(Some(2), None, None), 2);
        assert_eq!(accuracy(Some(2), None, Some(1)), 3);
        // A negative accuracy is not an encoding this build reads as widening.
        assert_eq!(accuracy(Some(-2), None, None), 0);
    }

    #[test]
    fn the_summary_is_never_failed() {
        let passed = vec![Check::passed(CheckCode::TimestampImprintOk, "ok")];
        let unknown = vec![Check::unknown(CheckCode::TimestampTsaPathUnknown, "?")];
        let failed = vec![Check::failed(CheckCode::TimestampImprintMismatch, "no")];
        let mixed = vec![
            Check::passed(CheckCode::TimestampImprintOk, "ok"),
            Check::failed(CheckCode::TimestampTsaPathUntrusted, "no"),
        ];
        assert_eq!(summary_check(&passed).status, CheckStatus::Passed);
        assert_eq!(summary_check(&unknown).status, CheckStatus::Unknown);
        // A failed token yields `unknown` at the signature level: it supplies
        // no proof of existence, which is missing information rather than a
        // finding against the signature (ETSI EN 319 102-1).
        assert_eq!(summary_check(&failed).status, CheckStatus::Unknown);
        assert_eq!(summary_check(&mixed).status, CheckStatus::Unknown);
    }

    #[test]
    fn serial_numbers_are_rendered_as_hex() {
        assert_eq!(hex(&[0x00, 0x2a, 0xff]), "002aff");
        assert_eq!(hex(&[]), "");
    }
}
