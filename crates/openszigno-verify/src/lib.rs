//! XMLDSig verification for Microsec e-Szignó dossiers.
//!
//! # What this phase can and cannot say
//!
//! This is phase 3 of the `verify` milestone. It validates the XMLDSig core
//! (canonicalization, reference digests, the signature value), enforces the
//! e-dossier reference-scope rules, binds the signing certificate through the
//! signed XAdES `SigningCertificate` property, verifies RFC 3161 signature
//! timestamps, validates the certification path against a caller-supplied
//! trust store and ETSI TS 119 612 trusted lists at a validation time a
//! verified timestamp may move, and checks revocation offline from the
//! signature's own `xades:RevocationValues` and a caller-supplied store.
//!
//! With revocation implemented, `valid` is reachable — and only reachable when
//! every emitted check passed. A caller that sees `indeterminate` has learned
//! that nothing failed, not that anything is trustworthy.
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
pub mod countersign;
pub mod coverage;
pub mod dsig;
pub mod embedded;
pub mod estimestamp;
pub mod policy;
pub mod references;
pub mod report;
pub mod revocation;
pub mod scope;
pub mod signature;
pub mod trust;
pub mod trustlist;
pub mod tsa;
pub mod xades;

use openszigno_core::{Error as CoreError, Limits, ParseOptions, XmlSource, id_map};

pub use c14n::{C14nAlgorithm, C14nBackend, C14nError, NodeSet, RoxmltreeC14n};
pub use codes::{Check, CheckCode, CheckStatus, Verdict};
pub use embedded::{EmbeddedRevocationValues, embedded_certificates, embedded_revocation_values};
pub use policy::{MAX_REVOCATION_ITEM_BYTES, PolicyReport, TrustListSnapshot, VerifyLimits};
pub use report::{
    CoverageState, CoverageVia, CoveringSignature, DocumentCoverage, SignatureReport,
    SignatureRole, SignatureScope, SigningCertificateBinding, ValidationTimeSource, VerifyReport,
    XadesReport,
};
pub use revocation::{CertificateRevocation, RevocationOrigin, RevocationStatus};
pub use trust::{
    Clock, FixedClock, MemoryRevocationStore, MemoryTrustStore, NoRevocation, NoTrust,
    RevocationPolicy, RevocationSource, ServiceIdentity, SystemClock, TrustAnchor,
    TrustAnchorOrigin, TrustServiceIdentity, TrustSource, format_rfc3339, parse_rfc3339,
};
pub use trustlist::{ServiceRecord, ServiceType, TrustList};
pub use tsa::{TimestampKind, TimestampReport};

use crate::certs::{CertificateSource, ParsedCertificate, dedup};
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

/// Everything the stages of one run share, gathered once before the first
/// signature is examined.
///
/// Stages A to C need only the XMLDSig [`dsig::Context`]; stages D to F also
/// need the trust material, the revocation policy and the clock reading, so
/// all of it is threaded through this one struct.
pub(crate) struct Context<'a, 'input, 's, 'o> {
    pub(crate) options: &'o VerifyOptions<'o>,
    /// The XMLDSig context stages A to C are driven from.
    pub(crate) dsig: dsig::Context<'a, 'input, 's>,
    /// The trust anchors: self-signed entries only, from either source.
    /// Nothing found in the dossier is ever one.
    pub(crate) anchors: Vec<ParsedCertificate>,
    /// Which [`trust::TrustAnchor`] each anchor's DER came from, so a
    /// validated path can be asked which anchor ended it.
    pub(crate) anchor_provenance: Vec<(Vec<u8>, &'o trust::TrustAnchor)>,
    /// Untrusted extra path candidates: every non-self-signed trust entry and
    /// every intermediate the trust source offered.
    pub(crate) store_intermediates: Vec<ParsedCertificate>,
    /// Every trusted-list service identity, whether or not it is also an
    /// anchor. These decide qualified status; they never grant trust.
    pub(crate) services: &'o [trust::TrustServiceIdentity],
    pub(crate) revocation_policy: trust::RevocationPolicy,
    /// The clock reading for this run.
    pub(crate) time: trust::UnixTime,
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
    //
    // A trusted list's anchors join the same set, keeping their provenance, so
    // that a path can later be asked *which* anchor ended it and whether that
    // anchor's service was granted at the validation time.
    let mut anchors: Vec<ParsedCertificate> = Vec::new();
    let mut anchor_provenance: Vec<(Vec<u8>, &trust::TrustAnchor)> = Vec::new();
    let mut store_certificates: Vec<ParsedCertificate> = Vec::new();
    // Every trusted-list service identity, whether or not it is also an anchor.
    // The identities that decide qualified status are usually the *issuing*
    // CAs, which are intermediates: a list that names them says nothing about
    // the root, and asking only the anchor would report `null` for exactly the
    // chains a trusted list exists to describe.
    let services = options.trust.services();
    for anchor in options.trust.anchors() {
        let source = match anchor.origin {
            trust::TrustAnchorOrigin::TrustList => CertificateSource::TrustList,
            trust::TrustAnchorOrigin::TrustStore => CertificateSource::TrustStore,
        };
        let Some(parsed) = ParsedCertificate::from_der(&anchor.der, source) else {
            continue;
        };
        if parsed.is_self_signed() {
            anchor_provenance.push((anchor.der.clone(), anchor));
            anchors.push(parsed);
        } else {
            // A non-self-signed entry is an extra path candidate, never an
            // anchor, whichever source offered it.
            store_certificates.push(parsed);
        }
    }
    let anchors = dedup(anchors);
    for der in options.trust.intermediates() {
        if let Some(parsed) = ParsedCertificate::from_der(der, CertificateSource::TrustStore) {
            store_certificates.push(parsed);
        }
    }
    let store_intermediates = dedup(store_certificates);
    dossier_checks.extend(options.trust.checks().iter().cloned());

    let revocation_policy = options.revocation.policy();
    dossier_checks.push(revocation::policy_check(revocation_policy));

    let context = Context {
        options,
        dsig: dsig::Context {
            source: source.text(),
            root,
            ids: &ids,
            namespace,
            allowed_namespaces: &options.parse.allowed_namespaces,
            signatures: &signature_nodes,
            backend: options.backend,
            limits: &options.limits,
            allow_legacy_algorithms: options.allow_legacy_algorithms,
        },
        anchors,
        anchor_provenance,
        store_intermediates,
        services,
        revocation_policy,
        time,
    };

    let mut signatures = Vec::new();
    let mut nested_unsupported: Vec<(usize, usize)> = Vec::new();
    let mut dossier_crls: Vec<Vec<u8>> = Vec::new();
    let mut dossier_ocsp: Vec<Vec<u8>> = Vec::new();
    let mut dossier_certificates: Vec<ParsedCertificate> = Vec::new();
    let over_limit = signature_nodes.len() > options.limits.max_signatures;
    for (index, node) in signature_nodes.iter().enumerate() {
        if over_limit && index >= options.limits.max_signatures {
            break;
        }
        let outcome = dsig::verify_signature(&context.dsig, *node, index);
        let mut report = outcome.report;

        // The signature's own revocation material. Untrusted like every other
        // thing a signer supplies: each item is signature-checked against the
        // path before it is believed.
        let (embedded_crls, embedded_ocsp) = xades::revocation_values(*node);
        // The container timestamps below are verified against everything the
        // dossier carries, not against one signature's share of it: an
        // `es:TimeStamp` is not owned by any signature, and a TSA's issuing CA
        // may sit in any signature's `CertificateValues`.
        for item in &embedded_crls {
            if !dossier_crls.contains(item) {
                dossier_crls.push(item.clone());
            }
        }
        for item in &embedded_ocsp {
            if !dossier_ocsp.contains(item) {
                dossier_ocsp.push(item.clone());
            }
        }
        dossier_certificates.extend(outcome.extra_certificates.iter().cloned());
        let revocation_data = revocation::RevocationData {
            embedded_crls: &embedded_crls,
            embedded_ocsp: &embedded_ocsp,
            store_crls: options.revocation.crls(),
            store_ocsp: options.revocation.ocsp_responses(),
            online_crls: options.revocation.online_crls(),
            online_ocsp: options.revocation.online_ocsp_responses(),
        };

        // --- Stage F: signature timestamps ----------------------------------
        // Timestamps are verified before the signer's own path, because a
        // verified token is what may move the validation time that path uses.
        let verified_gen_times = tsa::verify_signature_timestamps(
            &context,
            &outcome.timestamps,
            &outcome.extra_certificates,
            outcome.claimed_signing_time,
            revocation_data,
            &mut report,
        );

        // --- The validation time for this signature -------------------------
        // Precedence: an explicit `--at` always wins, then the earliest fully
        // verified timestamp's genTime, then the clock.
        let (signature_time, source) =
            match (&options.requested_time, verified_gen_times.iter().min()) {
                (Some(_), _) => (context.time, ValidationTimeSource::AtFlag),
                (None, Some(gen_time)) => (*gen_time, ValidationTimeSource::Timestamp),
                (None, None) => (context.time, ValidationTimeSource::CurrentTime),
            };
        report.validation_time = format_rfc3339(signature_time);
        report.validation_time_source = source;

        // --- Stage D: certificate path -------------------------------------
        if let Some(signer) = &outcome.signer {
            let signer_path = certs::verify_signer_path(
                &context,
                signer,
                &outcome.extra_certificates,
                signature_time,
                &mut report,
            );

            // --- Stage E: revocation ----------------------------------------
            revocation::check_signer_chain(
                &context,
                signer_path,
                &revocation_data,
                signature_time,
                source == ValidationTimeSource::Timestamp,
                &mut report,
            );
        } else {
            report.checks.push(Check::unknown(
                CheckCode::RevocationStatusUnknown,
                "no signing certificate was identified, so revocation could not be checked",
            ));
        }

        report.verdict = dsig::signature_verdict(&report.checks);
        if let Some(parent) = outcome.unsupported_nesting_parent {
            nested_unsupported.push((parent, index));
        }
        signatures.push(report);
    }

    // A nested signature this build does not support says nothing whatever
    // about the signature it was dropped into: the enclosing signature does
    // not cover its own unsigned properties, so nothing there can change what
    // it says. The parent is told, informationally, and keeps its verdict.
    for (parent, nested) in &nested_unsupported {
        if let Some(report) = signatures.get_mut(*parent) {
            report.checks.push(Check::info(
                CheckCode::NestedSignaturesUnsupported,
                format!(
                    "signature {nested} is nested inside this one in a shape this build does not support; it is reported on its own and does not affect this signature's verdict"
                ),
            ));
        }
    }

    // --- Stage G: container timestamps ------------------------------------
    // An `es:TimeStamp` protects the elements its `xades:Include` children
    // name, so verifying one needs the reference resolution, scope rule and
    // canonicalization a signature gets. It decides nothing about any
    // signature: it is a statement about the container.
    let document_nodes: Vec<_> = dsig::direct_children(root_element, namespace, "Documents")
        .next()
        .map(|documents| {
            dsig::direct_children(documents, namespace, "Document")
                .filter(|document| {
                    dsig::direct_children(*document, namespace, "DocumentProfile")
                        .next()
                        .is_some()
                })
                .collect()
        })
        .unwrap_or_default();
    let container_candidates = dedup({
        let mut candidates = dossier_certificates;
        candidates.extend(context.store_intermediates.iter().cloned());
        candidates
    });
    let container_revocation = revocation::RevocationData {
        embedded_crls: &dossier_crls,
        embedded_ocsp: &dossier_ocsp,
        store_crls: options.revocation.crls(),
        store_ocsp: options.revocation.ocsp_responses(),
        online_crls: options.revocation.online_crls(),
        online_ocsp: options.revocation.online_ocsp_responses(),
    };
    let mut container_timestamps: Vec<tsa::TimestampReport> = Vec::new();
    for source in estimestamp::collect(&context.dsig, root_element, &document_nodes) {
        if let Some(reason) = &source.unsupported {
            let check = estimestamp::unsupported_check(source.scope, reason);
            dossier_checks.push(check.clone());
            container_timestamps.push(tsa::TimestampReport {
                kind: source.kind(),
                document_index: source.document_index(),
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
            kind: source.kind(),
            document_index: source.document_index(),
            token: source.token.clone(),
            imprint_input: source.imprint_input.clone(),
            anchors: &context.anchors,
            extra_certificates: &container_candidates,
            limits: &options.limits,
            allow_legacy_algorithms: options.allow_legacy_algorithms,
            revocation: container_revocation,
            revocation_policy,
            // A container timestamp is not attached to any claimed signing
            // time, so there is no ordering claim to contradict.
            claimed_signing_time: None,
        });
        dossier_checks.push(estimestamp::summarise(
            source.scope,
            &token.report.checks,
            token.report.verified,
        ));
        container_timestamps.push(token.report);
    }
    let timestamps_verified = container_timestamps
        .iter()
        .filter(|report| report.verified)
        .count();

    if signatures.is_empty() {
        dossier_checks.push(Check::unknown(
            CheckCode::NoSignatures,
            "the dossier carries no ds:Signature, so there is nothing that could be valid",
        ));
    }

    // Incomplete support is not invalidity. A signature at a placement this
    // build does not describe cannot be judged, so it blocks the dossier with
    // `unknown` instead of sinking it with the `failed` placement check it
    // carries in its own right.
    let unsupported: Vec<String> = signatures
        .iter()
        .filter(|signature| unsupported_placement_only(signature))
        .map(|signature| signature.index.to_string())
        .collect();
    if !unsupported.is_empty() {
        dossier_checks.push(Check::unknown(
            CheckCode::SignaturesUnsupported,
            format!(
                "{} signature(s) sit at a placement this build does not support and could not be judged; indexes: {}",
                unsupported.len(),
                unsupported.join(", ")
            ),
        ));
    }

    // --- Stage H: document coverage ---------------------------------------
    // Which modelled documents the signatures actually cover. This is a
    // statement about the container, not about any signature: it changes no
    // signature's checks or verdict, and no signature's verdict changes it.
    let documents = coverage::document_coverage(
        &context.dsig,
        root_element,
        namespace,
        &dossier,
        &signature_nodes,
        &signatures,
    );
    dossier_checks.extend(coverage::coverage_checks(&documents));

    let counts = Counts {
        signatures: signatures.len(),
        signatures_valid: count(&signatures, Verdict::Valid),
        signatures_invalid: count(&signatures, Verdict::Invalid),
        signatures_indeterminate: count(&signatures, Verdict::Indeterminate),
        timestamps: dossier.timestamps_present,
        timestamps_verified,
        documents_covered: coverage::coverage_count(&documents, CoverageState::Covered),
        documents_uncovered: coverage::coverage_count(&documents, CoverageState::Uncovered),
        documents_undetermined: coverage::coverage_count(&documents, CoverageState::Undetermined),
    };

    let mut verdict = codes::verdict_of(&dossier_checks);
    for signature in &signatures {
        if unsupported_placement_only(signature) {
            continue;
        }
        verdict = verdict.worst(signature.verdict);
    }

    Ok(VerifyReport {
        verdict,
        verification_time: VerificationTime {
            requested: options.requested_time.clone(),
            effective: format_rfc3339(context.time),
            source: if options.requested_time.is_some() {
                TimeSource::Requested
            } else {
                TimeSource::SystemClock
            },
        },
        policy: PolicyReport::new(
            options.trust.configured(),
            options.allow_legacy_algorithms,
            revocation_policy,
        ),
        limits: options.limits.clone(),
        counts,
        checks: dossier_checks,
        timestamps: container_timestamps,
        documents,
        signatures,
    })
}

/// Whether a signature is one this build could not judge at all *because of
/// its placement*, and for no other reason.
///
/// Such a signature is left out of the dossier verdict: it carries a `failed`
/// `sig_placement_invalid` so a caller reading its own entry sees exactly what
/// happened, but a nesting this build does not implement is missing support,
/// not evidence of forgery, and under ETSI EN 319 102-1 that is INDETERMINATE.
/// The dossier is capped through the `signatures_unsupported` check instead. A
/// signature that failed anything *else* is folded in as usual: a binding or a
/// digest that actually fails is a finding whatever the placement.
fn unsupported_placement_only(signature: &SignatureReport) -> bool {
    signature.placement == SignatureScope::Unknown
        && signature
            .checks
            .iter()
            .filter(|check| check.status == CheckStatus::Failed)
            .all(|check| check.code == CheckCode::SigPlacementInvalid)
}

fn count(signatures: &[SignatureReport], verdict: Verdict) -> usize {
    signatures
        .iter()
        .filter(|signature| signature.verdict == verdict)
        .count()
}
