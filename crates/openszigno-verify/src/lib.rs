//! XMLDSig verification for Microsec e-Szignó dossiers.
//!
//! # What this phase can and cannot say
//!
//! This is phase 1 of the `verify` milestone. It validates the XMLDSig core
//! (canonicalization, reference digests, the signature value), enforces the
//! e-dossier reference-scope rules, and validates the certification path
//! against a caller-supplied trust store. Revocation and timestamps are
//! reported as `skipped`, which caps every verdict at `indeterminate`:
//! **this crate cannot return `valid`**, by construction, and a caller that
//! sees `indeterminate` has learned that nothing failed, not that anything is
//! trustworthy.
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

use openszigno_core::{Error as CoreError, Limits, ParseOptions, XmlSource, id_map};

pub use c14n::{C14nAlgorithm, C14nBackend, C14nError, NodeSet, RoxmltreeC14n};
pub use codes::{Check, CheckCode, CheckStatus, Verdict};
pub use policy::{PolicyReport, VerifyLimits};
pub use report::{SignatureReport, SignatureScope, VerifyReport};
pub use trust::{
    Clock, FixedClock, MemoryTrustStore, NoRevocation, NoTrust, RevocationSource, SystemClock,
    TrustSource, format_rfc3339, parse_rfc3339,
};

use crate::certs::{CertificateSource, ParsedCertificate, dedup, validate_path};
use crate::report::{Counts, VerificationTime};
use crate::trust::TimeSource;

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

        // --- Stage D: certificate path -------------------------------------
        if let Some(signer) = &outcome.signer {
            // Candidates: the signature's own certificates (ds:KeyInfo and the
            // XAdES CertificateValues) plus the trust store's intermediates.
            let mut candidates = outcome.extra_certificates.clone();
            candidates.extend(store_intermediates.iter().cloned());
            let candidates = dedup(candidates);
            let path = validate_path(signer, &candidates, &anchors, time, &options.limits);
            report.chain = path.chain;
            let status = match path.code {
                CheckCode::CertPathOk => CheckStatus::Passed,
                CheckCode::CertPathUnknown => CheckStatus::Unknown,
                _ => CheckStatus::Failed,
            };
            report
                .checks
                .push(Check::new(path.code, status, path.message));
        }

        // --- Stages E and F: reported, never silently omitted ---------------
        report.checks.push(Check::skipped(
            CheckCode::RevocationNotChecked,
            "revocation status is not checked in this phase",
        ));
        report.checks.push(Check::skipped(
            CheckCode::TimestampNotChecked,
            "timestamps are not verified in this phase",
        ));

        report.verdict = dsig::signature_verdict(&report.checks);
        signatures.push(report);
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
