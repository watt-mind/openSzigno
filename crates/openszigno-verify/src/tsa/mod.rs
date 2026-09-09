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
//!
//! The module is split by step: `token` holds the RFC 3161 wire formats and
//! the CMS signed-attribute checks, `imprint` holds the digest allowlist and
//! the imprint recomputation, and `path` holds the TSA certificate's purpose
//! and its certification path. What stays here is the token driver, the
//! reported types, and stage F's entry point.

mod imprint;
mod path;
#[cfg(test)]
mod tests;
mod token;

pub use token::{
    Accuracy, MessageImprint, PkiStatusInfo, TimeStampResp, TstInfo, token_certificates,
};

use path::{TsaPath, check_tsa_certificate};
use token::{
    OID_CT_TST_INFO, OID_SIGNED_DATA, accuracy_seconds, content_info, find_signer_certificate, hex,
    single_signer, verify_signer_info,
};

use der::asn1::OctetString;
use der::{Decode, Encode};
use serde::Serialize;

use cms::cert::CertificateChoices;
use cms::signed_data::SignedData;

use crate::certs::{CertificateSource, CertificateSummary, ChainEntry, ParsedCertificate};
use crate::codes::{Check, CheckCode, CheckStatus};
use crate::policy::{Digest, VerifyLimits};
use crate::trust::{UnixTime, format_rfc3339};

/// The largest token this crate will parse, so an attacker-supplied
/// `EncapsulatedTimeStamp` cannot turn into unbounded work.
pub const MAX_TOKEN_BYTES: usize = 512 * 1024;

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
///
/// This entry point knows nothing about where the anchors came from, so every
/// one of them may end the TSA's path at any time. A caller holding
/// trusted-list anchors must use [`verify_token_at`] instead, so that a
/// TSA/QTST service the list has stopped vouching for cannot anchor one.
pub fn verify_token(input: &TokenInput<'_>) -> TokenOutcome {
    verify_token_at(input, crate::certs::AnchorStatus::none())
}

/// [`verify_token`], told what the caller knows about each anchor.
///
/// `status` decides whether the anchor the TSA's own path reaches was granted
/// as a qualified timestamping authority (TSA/QTST) at the token's `genTime` —
/// the instant the authority claims it spoke, and so the instant it had to be
/// entitled to speak.
pub fn verify_token_at(
    input: &TokenInput<'_>,
    status: crate::certs::AnchorStatus<'_>,
) -> TokenOutcome {
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

    let imprint_algorithm = imprint::check_imprint(&tst_info, input, &mut checks);

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
        let TsaPath {
            mut chain,
            path,
            candidates,
        } = check_tsa_certificate(tsa, &certificates, input, status, gen_time, &mut checks);

        // --- The TSA chain's revocation -------------------------------------
        // Checked at `genTime`, the same instant the chain itself is validated
        // at: the question is whether the authority was entitled to speak when
        // it spoke.
        if !path.is_empty() {
            let outcome = crate::revocation::check_path_at(
                &crate::revocation::PathRevocationInput {
                    anchors: input.anchors,
                    path: &path,
                    candidates: &candidates,
                    data: &input.revocation,
                    time: gen_time,
                    // The instant a TSA's own chain is validated at is the
                    // `genTime` the token asserts, so it cannot also be the
                    // proof that dismisses a revocation dated after it. A TSA
                    // certificate revoked after its own genTime stays
                    // `unknown`.
                    time_is_proven: false,
                    policy: input.revocation_policy,
                    role: crate::revocation::ChainRole::TimestampAuthority,
                    limits: input.limits,
                },
                status,
            );
            for (entry, status) in chain.iter_mut().zip(outcome.per_certificate) {
                entry.revocation = Some(status);
            }
            checks.push(outcome.check);
            checks.extend(outcome.notes);
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

/// Stage F: verify every `xades:SignatureTimeStamp` this signature carries.
///
/// A TSA's issuing CA is often carried in the enclosing signature's
/// `xades:CertificateValues` rather than inside the token, so the token's own
/// certificate set, the signature's candidates, and the trust store's
/// intermediates are offered together. All three are untrusted path
/// candidates; only the trust store supplies anchors.
///
/// Returns the `genTime` of every token that verified in full, which is the
/// only thing that may move this signature's validation time.
pub(crate) fn verify_signature_timestamps(
    context: &crate::Context<'_, '_, '_, '_>,
    timestamps: &[crate::dsig::TimestampSource],
    extra_certificates: &[ParsedCertificate],
    claimed_signing_time: Option<UnixTime>,
    revocation_data: crate::revocation::RevocationData<'_>,
    report: &mut crate::report::SignatureReport,
) -> Vec<UnixTime> {
    let mut timestamp_candidates = extra_certificates.to_vec();
    timestamp_candidates.extend(context.store_intermediates.iter().cloned());
    let timestamp_candidates = crate::certs::dedup(timestamp_candidates);
    let mut verified_gen_times: Vec<UnixTime> = Vec::new();
    for source in timestamps {
        if let Some(reason) = &source.unsupported {
            let check = Check::skipped(CheckCode::TimestampNotChecked, reason.clone());
            report.checks.push(check.clone());
            report.timestamps.push(TimestampReport {
                kind: source.kind,
                document_index: None,
                gen_time: None,
                accuracy_seconds: None,
                serial_hex: None,
                imprint_algorithm: None,
                tsa_certificate: None,
                chain: Vec::new(),
                verified: false,
                checks: vec![check],
            });
            continue;
        }
        let token = verify_token_at(
            &TokenInput {
                kind: source.kind,
                document_index: None,
                token: source.token.clone(),
                imprint_input: source.imprint_input.clone(),
                anchors: &context.anchors,
                extra_certificates: &timestamp_candidates,
                limits: &context.options.limits,
                allow_legacy_algorithms: context.options.allow_legacy_algorithms,
                revocation: revocation_data,
                revocation_policy: context.revocation_policy,
                claimed_signing_time,
            },
            crate::certs::AnchorStatus::new(&context.anchor_provenance),
        );
        report.checks.push(summary_check(&token.report.checks));
        // The TSA chain's own revocation answer belongs to this signature's
        // verdict too: a timestamp signed under a revoked TSA certificate must
        // not leave a signature looking clean.
        if let Some(check) = revocation_check(&token.report.checks) {
            report.checks.push(check.clone());
        }
        if token.report.verified
            && let Some(gen_time) = token.gen_time
        {
            verified_gen_times.push(gen_time);
        }
        report.timestamps.push(token.report);
    }
    if report.timestamps.is_empty() {
        report.checks.push(Check::unknown(
            CheckCode::SignatureTimestampAbsent,
            "the signature carries no xades:SignatureTimeStamp, so nothing proves when it existed",
        ));
    } else {
        // Informational: what a present timestamp is worth is decided by its
        // own checks, which are folded in above. Saying "present" is a
        // statement about the document, not an unresolved question.
        report.checks.push(Check::info(
            CheckCode::SignatureTimestampPresent,
            "the signature carries at least one xades:SignatureTimeStamp; a timestamp proves existence, not validity",
        ));
    }
    verified_gen_times
}
