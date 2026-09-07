//! XMLDSig verification for Microsec e-Szignó dossiers.
//!
//! # What this phase can and cannot say
//!
//! This is phase 2 of the `verify` milestone. It validates the XMLDSig core
//! (canonicalization, reference digests, the signature value), enforces the
//! e-dossier reference-scope rules, binds the signing certificate through the
//! signed XAdES `SigningCertificate` property, verifies RFC 3161 signature
//! timestamps, and validates the certification path against a caller-supplied
//! trust store at a validation time a verified timestamp may move. Revocation
//! is still reported as `skipped`, which caps every verdict at
//! `indeterminate`: **this crate cannot return `valid`**, by construction, and
//! a caller that sees `indeterminate` has learned that nothing failed, not
//! that anything is trustworthy.
//!
//! # Structure
//!
//! The crate owns the whole pipeline: reference resolution, the transform and
//! algorithm allowlists, canonicalization, and path validation. Nothing is
//! delegated to a general-purpose XMLDSig library, because those libraries do
//! not know the e-dossier placement rules and would own exactly the decisions
//! this project has stricter rules about.
//!
//! All I/O arrives through the injected [`Clock`], [`TrustSource`], and
//! [`RevocationSource`] traits. The crate itself opens no file and no socket.

#![forbid(unsafe_code)]

pub mod c14n;
pub mod certs;
pub mod codes;
pub mod dsig;
pub mod policy;
pub mod report;
pub mod trust;
pub mod tsa;
pub mod xades;

use openszigno_core::{Error as CoreError, Limits, ParseOptions, XmlSource, id_map};

pub use c14n::{C14nAlgorithm, C14nBackend, C14nError, NodeSet, RoxmltreeC14n};
pub use codes::{Check, CheckCode, CheckStatus, Verdict};
pub use policy::{PolicyReport, VerifyLimits};
pub use report::{
    SignatureReport, SignatureScope, SigningCertificateBinding, ValidationTimeSource, VerifyReport,
    XadesReport,
};
pub use trust::{
    Clock, FixedClock, MemoryTrustStore, NoRevocation, NoTrust, RevocationSource, SystemClock,
    TrustSource, format_rfc3339, parse_rfc3339,
};
pub use tsa::{TimestampKind, TimestampReport};

use crate::certs::{CertificateSource, ParsedCertificate, PathPurpose, dedup, validate_path};
use crate::report::{Counts, VerificationTime};
use crate::trust::TimeSource;
use crate::tsa::{TokenInput, verify_token};

/// How one dossier is verified.
pub struct VerifyOptions<'a> {
    pub parse: ParseOptions,
    pub limits: VerifyLimits,
    pub clock: &'a dyn Clock,
    /// The `--at` value as the caller wrote it, for the report only.
    pub requested_time: Option<String>,
    pub trust: &'a dyn TrustSource,
    /// Admit SHA-1 digests and RSA-SHA1 signature methods for diagnosis only.
    /// A legacy algorithm never yields a `passed` check, so this flag can only
    /// lower a verdict, never raise one. MD5, HMAC, DSA, and RSA keys below
    /// 2048 bits stay refused whatever it is set to.
    pub allow_legacy_algorithms: bool,
    pub revocation: &'a dyn RevocationSource,
    pub backend: &'a dyn C14nBackend,
}

impl<'a> VerifyOptions<'a> {
    /// Offline defaults: the system clock, no trust anchors, no revocation
    /// data, and the in-tree canonicalization backend.
    pub fn new(
        clock: &'a dyn Clock,
        trust: &'a dyn TrustSource,
        revocation: &'a dyn RevocationSource,
        backend: &'a dyn C14nBackend,
    ) -> Self {
        Self {
            parse: ParseOptions::default(),
            limits: VerifyLimits::default(),
            clock,
            requested_time: None,
            trust,
            allow_legacy_algorithms: false,
            revocation,
            backend,
        }
    }

    fn core_limits(&self) -> &Limits {
        &self.parse.limits
    }
}

/// Verify every `ds:Signature` in a dossier.
///
/// A structural failure is returned as a core [`CoreError`] and aborts before
/// any signature is examined, so a caller can still tell "this is not a
/// dossier" apart from "this dossier's signatures do not verify".
pub fn verify(bytes: &[u8], options: &VerifyOptions<'_>) -> Result<VerifyReport, CoreError> {
    // The structural rules run first and unchanged: they are what guarantees a
    // unique ID space, resolvable OBJREFs, and a bounded document.
    let dossier = openszigno_core::parse_with_options(bytes, &options.parse)?;

    let source = XmlSource::decode(bytes, options.core_limits())?;
    let tree = source.parse_tree(options.core_limits())?;
    let root = tree.root();
    let root_element = tree.root_element();
    let namespace = root_element.tag_name().namespace().unwrap_or_default();
    let ids = id_map(root_element)?;

    let time = options.clock.unix_time();
    let mut dossier_checks: Vec<Check> = Vec::new();

    let signature_nodes: Vec<_> = root_element
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(openszigno_core::XMLDSIG_NAMESPACE)
                && node.tag_name().name() == "Signature"
        })
        .collect();

    if signature_nodes.len() > options.limits.max_signatures {
        dossier_checks.push(Check::failed(
            CheckCode::SignatureLimitExceeded,
            format!(
                "the dossier holds more than {} signatures",
                options.limits.max_signatures
            ),
        ));
    } else {
        dossier_checks.push(Check::passed(
            CheckCode::SignatureCountWithinLimits,
            "the number of signatures is within the verification limits",
        ));
    }

    // The trust store supplies both roles: a self-signed entry is an anchor, a
    // non-self-signed one is an extra untrusted intermediate. Nothing found in
    // the dossier is ever an anchor.
    let store: Vec<ParsedCertificate> = dedup(
        options
            .trust
            .anchors()
            .iter()
            .chain(options.trust.intermediates())
            .filter_map(|der| ParsedCertificate::from_der(der, CertificateSource::TrustStore))
            .collect(),
    );
    let (anchors, store_intermediates): (Vec<_>, Vec<_>) = store
        .into_iter()
        .partition(ParsedCertificate::is_self_signed);

    let context = dsig::Context {
        source: source.text(),
        root,
        ids: &ids,
        namespace,
        allowed_namespaces: &options.parse.allowed_namespaces,
        backend: options.backend,
        limits: &options.limits,
        allow_legacy_algorithms: options.allow_legacy_algorithms,
    };

    let mut signatures = Vec::new();
    let over_limit = signature_nodes.len() > options.limits.max_signatures;
    for (index, node) in signature_nodes.iter().enumerate() {
        if over_limit && index >= options.limits.max_signatures {
            break;
        }
        let outcome = dsig::verify_signature(&context, *node, index);
        let mut report = outcome.report;

        // --- Stage F: signature timestamps ----------------------------------
        // Timestamps are verified before the signer's own path, because a
        // verified token is what may move the validation time that path uses.
        //
        // A TSA's issuing CA is often carried in the enclosing signature's
        // `xades:CertificateValues` rather than inside the token, so the
        // token's own certificate set, the signature's candidates, and the
        // trust store's intermediates are offered together. All three are
        // untrusted path candidates; only the trust store supplies anchors.
        let mut timestamp_candidates = outcome.extra_certificates.clone();
        timestamp_candidates.extend(store_intermediates.iter().cloned());
        let timestamp_candidates = dedup(timestamp_candidates);
        let mut verified_gen_times: Vec<crate::trust::UnixTime> = Vec::new();
        for source in &outcome.timestamps {
            if let Some(reason) = &source.unsupported {
                let check = Check::skipped(CheckCode::TimestampNotChecked, reason.clone());
                report.checks.push(check.clone());
                report.timestamps.push(tsa::TimestampReport {
                    kind: source.kind,
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
            let token = verify_token(&TokenInput {
                kind: source.kind,
                token: source.token.clone(),
                imprint_input: source.imprint_input.clone(),
                anchors: &anchors,
                extra_certificates: &timestamp_candidates,
                limits: &options.limits,
                allow_legacy_algorithms: options.allow_legacy_algorithms,
                claimed_signing_time: outcome.claimed_signing_time,
            });
            report.checks.push(tsa::summary_check(&token.report.checks));
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
            report.checks.push(Check::unknown(
                CheckCode::SignatureTimestampPresent,
                "the signature carries at least one xades:SignatureTimeStamp; a timestamp proves existence, not validity",
            ));
        }

        // --- The validation time for this signature -------------------------
        // Precedence: an explicit `--at` always wins, then the earliest fully
        // verified timestamp's genTime, then the clock.
        let (signature_time, source) =
            match (&options.requested_time, verified_gen_times.iter().min()) {
                (Some(_), _) => (time, ValidationTimeSource::AtFlag),
                (None, Some(gen_time)) => (*gen_time, ValidationTimeSource::Timestamp),
                (None, None) => (time, ValidationTimeSource::CurrentTime),
            };
        report.validation_time = format_rfc3339(signature_time);
        report.validation_time_source = source;

        // --- Stage D: certificate path -------------------------------------
        if let Some(signer) = &outcome.signer {
            // Candidates: the signature's own certificates (ds:KeyInfo and the
            // XAdES CertificateValues) plus the trust store's intermediates.
            let mut candidates = outcome.extra_certificates.clone();
            candidates.extend(store_intermediates.iter().cloned());
            let candidates = dedup(candidates);
            let path = validate_path(
                signer,
                &candidates,
                &anchors,
                signature_time,
                &options.limits,
                PathPurpose::Signing,
            );
            report.chain = path.chain;
            let status = match path.code {
                CheckCode::CertPathOk => CheckStatus::Passed,
                // Giving up is not a finding: an exhausted search means the
                // tool stopped looking, not that no path exists.
                CheckCode::CertPathUnknown | CheckCode::CertPathSearchExhausted => {
                    CheckStatus::Unknown
                }
                _ => CheckStatus::Failed,
            };
            report
                .checks
                .push(Check::new(path.code, status, path.message));
        }

        // --- Stage E: reported, never silently omitted ----------------------
        report.checks.push(Check::skipped(
            CheckCode::RevocationNotChecked,
            "revocation status is not checked in this phase",
        ));

        report.verdict = dsig::signature_verdict(&report.checks);
        signatures.push(report);
    }

    if dossier.timestamps_present > 0 {
        // A dossier-level `es:TimeStamp` protects the elements it references,
        // so verifying one needs the reference machinery M3 adds. Reporting it
        // as unchecked is the honest answer; guessing at what it covers and
        // then reporting a match would not be.
        dossier_checks.push(Check::skipped(
            CheckCode::DossierTimestampNotValidated,
            format!(
                "{} dossier-level es:TimeStamp element(s) are present and are not validated in this release",
                dossier.timestamps_present
            ),
        ));
    }

    if signatures.is_empty() {
        dossier_checks.push(Check::unknown(
            CheckCode::NoSignatures,
            "the dossier carries no ds:Signature, so there is nothing that could be valid",
        ));
    }

    let counts = Counts {
        signatures: signatures.len(),
        signatures_valid: count(&signatures, Verdict::Valid),
        signatures_invalid: count(&signatures, Verdict::Invalid),
        signatures_indeterminate: count(&signatures, Verdict::Indeterminate),
        timestamps: dossier.timestamps_present,
    };

    let mut verdict = codes::verdict_of(&dossier_checks);
    for signature in &signatures {
        verdict = verdict.worst(signature.verdict);
    }

    Ok(VerifyReport {
        verdict,
        verification_time: VerificationTime {
            requested: options.requested_time.clone(),
            effective: format_rfc3339(time),
            source: if options.requested_time.is_some() {
                TimeSource::Requested
            } else {
                TimeSource::SystemClock
            },
        },
        policy: PolicyReport::new(options.trust.configured(), options.allow_legacy_algorithms),
        limits: options.limits.clone(),
        counts,
        checks: dossier_checks,
        signatures,
    })
}

fn count(signatures: &[SignatureReport], verdict: Verdict) -> usize {
    signatures
        .iter()
        .filter(|signature| signature.verdict == verdict)
        .count()
}
