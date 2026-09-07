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
pub mod dsig;
pub mod estimestamp;
pub mod policy;
pub mod report;
pub mod revocation;
pub mod trust;
pub mod trustlist;
pub mod tsa;
pub mod xades;

use openszigno_core::{Error as CoreError, Limits, ParseOptions, XmlSource, id_map};

pub use c14n::{C14nAlgorithm, C14nBackend, C14nError, NodeSet, RoxmltreeC14n};
pub use codes::{Check, CheckCode, CheckStatus, Verdict};
pub use policy::{PolicyReport, TrustListSnapshot, VerifyLimits};
pub use report::{
    CoverageState, CoverageVia, CoveringSignature, DocumentCoverage, SignatureReport,
    SignatureScope, SigningCertificateBinding, ValidationTimeSource, VerifyReport, XadesReport,
};
pub use revocation::{CertificateRevocation, RevocationOrigin, RevocationStatus};
pub use trust::{
    Clock, FixedClock, MemoryRevocationStore, MemoryTrustStore, NoRevocation, NoTrust,
    RevocationPolicy, RevocationSource, ServiceIdentity, SystemClock, TrustAnchor,
    TrustAnchorOrigin, TrustServiceIdentity, TrustSource, format_rfc3339, parse_rfc3339,
};
pub use trustlist::{ServiceRecord, ServiceType, TrustList};
pub use tsa::{TimestampKind, TimestampReport};

use crate::certs::{CertificateSource, ParsedCertificate, PathPurpose, dedup, validate_path};
use crate::report::{Counts, VerificationTime};
use crate::trust::TimeSource;
use der::Decode as _;
use openszigno_core::roxmltree::Node;
/// Every X.509 certificate a dossier carries, as DER, deduplicated.
///
/// This exists for one caller: the CLI's `--online` fetcher, which has to know
/// *which* certificates a run might need revocation data about before it can
/// decide whether anything is worth fetching. It is a read of the document and
/// nothing more — no certificate returned here is trusted, validated, or
/// placed in a path; that all still happens inside [`verify`].
///
/// Three places are read, because between them they hold everything a real
/// dossier carries: `ds:KeyInfo/ds:X509Data/ds:X509Certificate`, every
/// `xades:EncapsulatedX509Certificate` under the qualifying properties
/// (`CertificateValues` and `TimeStampValidationData` alike), and the
/// `certificates` set of every RFC 3161 token, which is usually the only place
/// a timestamp authority's own leaf appears.
pub fn embedded_certificates(
    bytes: &[u8],
    options: &ParseOptions,
) -> Result<Vec<Vec<u8>>, CoreError> {
    use base64::Engine as _;

    let limits = &options.limits;
    let source = XmlSource::decode(bytes, limits)?;
    let tree = source.parse_tree(limits)?;
    let mut certificates: Vec<Vec<u8>> = Vec::new();
    let decode = |text: String| -> Option<Vec<u8>> {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .ok()
    };
    let push = |der: Vec<u8>, certificates: &mut Vec<Vec<u8>>| {
        if certificates.len() < MAX_EMBEDDED_CERTIFICATES
            && x509_cert::Certificate::from_der(&der).is_ok()
            && !certificates.contains(&der)
        {
            certificates.push(der);
        }
    };
    for node in tree.descendants().filter(|node| node.is_element()) {
        let text = || -> String {
            node.children()
                .filter(openszigno_core::roxmltree::Node::is_text)
                .filter_map(|child| child.text())
                .collect()
        };
        match node.tag_name().name() {
            "X509Certificate" | "EncapsulatedX509Certificate" => {
                if let Some(der) = decode(text()) {
                    push(der, &mut certificates);
                }
            }
            "EncapsulatedTimeStamp" => {
                if let Some(token) = decode(text()) {
                    for der in tsa::token_certificates(&token) {
                        push(der, &mut certificates);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(certificates)
}

/// The CRLs and OCSP responses a dossier carries as XAdES validation data, in
/// that order, each item DER.
pub type EmbeddedRevocationValues = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Every CRL and OCSP response a dossier carries as XAdES validation data, as
/// DER: the CRLs first, then the OCSP responses.
///
/// Like [`embedded_certificates`], this is a read for the CLI's `--online`
/// fetcher, which must know what the dossier already answers for before it
/// decides whether anything is worth fetching. It is the same harvest
/// [`verify`] performs per signature, widened to the whole document, and it
/// confers no trust on anything: every item is still signature-checked against
/// an authorised issuer inside the verifier before it is believed.
pub fn embedded_revocation_values(
    bytes: &[u8],
    options: &ParseOptions,
) -> Result<EmbeddedRevocationValues, CoreError> {
    let limits = &options.limits;
    let source = XmlSource::decode(bytes, limits)?;
    let tree = source.parse_tree(limits)?;
    let mut crls: Vec<Vec<u8>> = Vec::new();
    let mut ocsp: Vec<Vec<u8>> = Vec::new();
    for node in tree.descendants().filter(|node| node.is_element()) {
        let target = match node.tag_name().name() {
            "EncapsulatedCRLValue" => &mut crls,
            "EncapsulatedOCSPValue" => &mut ocsp,
            _ => continue,
        };
        if target.len() >= MAX_EMBEDDED_CERTIFICATES {
            continue;
        }
        let text: String = node
            .children()
            .filter(openszigno_core::roxmltree::Node::is_text)
            .filter_map(|child| child.text())
            .collect();
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        use base64::Engine as _;
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(compact.as_bytes())
            && !target.contains(&der)
        {
            target.push(der);
        }
    }
    Ok((crls, ocsp))
}

/// The largest number of certificates [`embedded_certificates`] will return.
/// The document is attacker-controlled and every entry costs work upstream.
const MAX_EMBEDDED_CERTIFICATES: usize = 256;

/// When eIDAS (Regulation (EU) 910/2014) began to apply, which is the line
/// after which a qualified certificate must carry `QcCompliance` itself.
/// Before it, the trusted list's own record is the whole story, because the
/// statement had not been mandated yet.
use crate::trustlist::EIDAS_APPLICATION_DATE;
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
    let mut dossier_crls: Vec<Vec<u8>> = Vec::new();
    let mut dossier_ocsp: Vec<Vec<u8>> = Vec::new();
    let mut dossier_certificates: Vec<ParsedCertificate> = Vec::new();
    let over_limit = signature_nodes.len() > options.limits.max_signatures;
    for (index, node) in signature_nodes.iter().enumerate() {
        if over_limit && index >= options.limits.max_signatures {
            break;
        }
        let outcome = dsig::verify_signature(&context, *node, index);
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
            let token = verify_token(&TokenInput {
                kind: source.kind,
                document_index: None,
                token: source.token.clone(),
                imprint_input: source.imprint_input.clone(),
                anchors: &anchors,
                extra_certificates: &timestamp_candidates,
                limits: &options.limits,
                allow_legacy_algorithms: options.allow_legacy_algorithms,
                revocation: revocation_data,
                revocation_policy,
                claimed_signing_time: outcome.claimed_signing_time,
            });
            report.checks.push(tsa::summary_check(&token.report.checks));
            // The TSA chain's own revocation answer belongs to this signature's
            // verdict too: a timestamp signed under a revoked TSA certificate
            // must not leave a signature looking clean.
            if let Some(check) = tsa::revocation_check(&token.report.checks) {
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
            // Informational: what a present timestamp is worth is decided by
            // its own checks, which are folded in above. Saying "present" is a
            // statement about the document, not an unresolved question.
            report.checks.push(Check::info(
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
            let mut chain = path.chain;
            report.checks.extend(path.advisories);
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

            // --- The anchor's provenance, and what the chain makes it -------
            if let Some(anchor) = path.path.last() {
                // When the same certificate is both a store anchor and a
                // trusted-list identity, the list is the stronger provenance
                // and the one worth reporting: it says *who* vouches for the
                // CA, where a directory only says that somebody copied it in.
                let listed = services.iter().any(|service| {
                    matches!(&service.identity, trust::ServiceIdentity::Certificate(der) if *der == anchor.der)
                });
                let provenance = anchor_provenance
                    .iter()
                    .find(|(der, _)| *der == anchor.der)
                    .map(|(_, anchor)| *anchor);
                if let Some(entry) = chain.last_mut() {
                    entry.trust_anchor_origin = if listed {
                        Some(trust::TrustAnchorOrigin::TrustList)
                    } else {
                        provenance.map(|anchor| anchor.origin)
                    };
                }
                let outcome = qualification(services, &path.path, signature_time);
                report.qualified = outcome.qualified;
                report.qualified_signature_device = outcome.device;
                report.qualified_service = outcome.service.clone();
                if let Some(certificate) = report.signing_certificate.as_mut() {
                    certificate.qualified = outcome.qualified;
                }
                report.checks.push(outcome.check);
            }

            // --- Stage E: revocation ----------------------------------------
            if path.path.is_empty() {
                // No validated path means no issuer to check anything against.
                report.checks.push(match revocation_policy {
                    trust::RevocationPolicy::NotChecked => Check::skipped(
                        CheckCode::RevocationNotChecked,
                        "revocation checking was switched off by the caller",
                    ),
                    trust::RevocationPolicy::Offline | trust::RevocationPolicy::Online => Check::unknown(
                        CheckCode::RevocationStatusUnknown,
                        "no validated certification path was available, so revocation could not be checked",
                    ),
                });
            } else {
                let outcome = revocation::check_path(&revocation::PathRevocationInput {
                    anchors: &anchors,
                    path: &path.path,
                    candidates: &candidates,
                    data: &revocation_data,
                    time: signature_time,
                    // Only a fully verified signature timestamp *proves* the
                    // validation time; `--at` and the clock merely assert it.
                    // That difference decides whether a revocation dated after
                    // it may be dismissed.
                    time_is_proven: source == ValidationTimeSource::Timestamp,
                    policy: revocation_policy,
                    role: revocation::ChainRole::Signer,
                    limits: &options.limits,
                });
                for (entry, status) in chain.iter_mut().zip(outcome.per_certificate) {
                    entry.revocation = Some(status);
                }
                report.checks.push(outcome.check);
                report.checks.extend(outcome.notes);
            }
            report.chain = chain;
        } else {
            report.checks.push(Check::unknown(
                CheckCode::RevocationStatusUnknown,
                "no signing certificate was identified, so revocation could not be checked",
            ));
        }

        report.verdict = dsig::signature_verdict(&report.checks);
        signatures.push(report);
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
        candidates.extend(store_intermediates.iter().cloned());
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
    for source in estimestamp::collect(&context, root_element, &document_nodes) {
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
            anchors: &anchors,
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

    // --- Stage H: document coverage ---------------------------------------
    // Which modelled documents the signatures actually cover. This is a
    // statement about the container, not about any signature: it changes no
    // signature's checks or verdict, and no signature's verdict changes it.
    let documents = document_coverage(
        &context,
        root_element,
        namespace,
        &dossier,
        &signature_nodes,
        &signatures,
    );
    dossier_checks.extend(coverage_checks(&documents));

    let counts = Counts {
        signatures: signatures.len(),
        signatures_valid: count(&signatures, Verdict::Valid),
        signatures_invalid: count(&signatures, Verdict::Invalid),
        signatures_indeterminate: count(&signatures, Verdict::Indeterminate),
        timestamps: dossier.timestamps_present,
        timestamps_verified,
        documents_covered: coverage_count(&documents, CoverageState::Covered),
        documents_uncovered: coverage_count(&documents, CoverageState::Uncovered),
        documents_undetermined: coverage_count(&documents, CoverageState::Undetermined),
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

/// One signature, as the coverage pass sees it.
struct CoverageSource<'a, 'input> {
    /// The index into `data.signatures`, or `None` for a signature the run
    /// never examined because the dossier is over the signature limit.
    signature_index: Option<usize>,
    node: Node<'a, 'input>,
    scope: SignatureScope,
    verdict: Verdict,
    coverage: dsig::SignatureCoverage,
}

/// Which `es:Document` a signature sits inside, if any.
///
/// Used only to decide which documents a signature that could **not** be
/// evaluated might have covered, so an unreadable signature clouds the
/// document it is in rather than the whole container.
fn containing_document<'a, 'input>(
    signature: Node<'a, 'input>,
    namespace: &str,
) -> Option<Node<'a, 'input>> {
    signature.ancestors().find(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some(namespace)
            && node.tag_name().name() == "Document"
    })
}

/// The per-document signature coverage of one dossier, in source order.
///
/// Coverage is decided by **resolved references** and by the implemented
/// e-dossier scope rules. Placement never grants coverage on its own: it
/// selects which mandated set applies, and a signature whose mandated set is
/// incomplete covers nothing. The result is deliberately independent of every
/// cryptographic outcome — a document covered by a signature that does not
/// verify is `covered_unverified`, and the signature's own verdict carries the
/// cryptographic finding.
fn document_coverage<'a, 'input>(
    context: &dsig::Context<'a, 'input, '_>,
    root_element: Node<'a, 'input>,
    namespace: &str,
    dossier: &openszigno_core::Dossier,
    signature_nodes: &[Node<'a, 'input>],
    signatures: &[SignatureReport],
) -> Vec<DocumentCoverage> {
    let sources: Vec<CoverageSource<'a, 'input>> = signature_nodes
        .iter()
        .enumerate()
        .map(|(index, node)| match signatures.get(index) {
            Some(report) => CoverageSource {
                signature_index: Some(index),
                node: *node,
                scope: report.scope,
                verdict: report.verdict,
                coverage: dsig::signature_coverage(context, *node, &report.checks),
            },
            // Over the signature limit, so it was never examined. It is not
            // evidence of anything, and it is not evidence of nothing either.
            None => CoverageSource {
                signature_index: None,
                node: *node,
                scope: SignatureScope::Unknown,
                verdict: Verdict::Indeterminate,
                coverage: dsig::SignatureCoverage {
                    resolved: Vec::new(),
                    scope_complete: false,
                    undetermined: Some(
                        "the signature was not examined because the dossier is over the signature limit",
                    ),
                },
            },
        })
        .collect();

    let Some(documents_node) = dsig::direct_child(root_element, namespace, "Documents") else {
        return Vec::new();
    };
    // The parser's own words for the documents it skipped, in source order.
    let mut skipped = dossier
        .warnings
        .iter()
        .filter(|warning| {
            warning.code == openszigno_core::StructuralWarningCode::DocumentWithoutProfile
        })
        .map(|warning| warning.message.clone());

    let mut modelled = 0usize;
    let mut report = Vec::new();
    for node in dsig::direct_children(documents_node, namespace, "Document") {
        let Some(profile) = dsig::direct_child(node, namespace, "DocumentProfile") else {
            report.push(DocumentCoverage {
                index: None,
                object_ref: None,
                nested_dossier: false,
                coverage: CoverageState::NotModelled,
                covered_by: Vec::new(),
                reason: Some(skipped.next().unwrap_or_else(|| {
                    "the document carries no DocumentProfile and was not modelled".to_owned()
                })),
            });
            continue;
        };
        let Some(document) = dossier.documents.get(modelled) else {
            continue;
        };
        modelled += 1;
        let payload = dsig::direct_children(node, openszigno_core::XMLDSIG_NAMESPACE, "Object")
            .find(|object| object.attribute("Id") == Some(document.object_ref.as_str()));

        let mut covered_by = Vec::new();
        for source in &sources {
            if source.coverage.undetermined.is_some() || !source.coverage.scope_complete {
                continue;
            }
            let Some(signature_index) = source.signature_index else {
                continue;
            };
            let resolved = &source.coverage.resolved;
            let via = match source.scope {
                // Direct: placed in *this* document, and its references
                // resolve to this document's profile and payload object.
                SignatureScope::Document
                    if source.node.parent() == Some(node)
                        && dsig::covers(resolved, profile)
                        && payload.is_some_and(|object| dsig::covers(resolved, object)) =>
                {
                    CoverageVia::Direct
                }
                // Through the frame: the dossier-level signature's references
                // resolve to `es:Documents`, or to an ancestor of it.
                SignatureScope::Dossier if dsig::covers(resolved, node) => CoverageVia::Frame,
                _ => continue,
            };
            covered_by.push(CoveringSignature {
                signature_index,
                via,
                verdict: source.verdict,
            });
        }

        let best = covered_by.iter().map(|entry| entry.verdict).min();
        let (coverage, mut reason) = match best {
            Some(Verdict::Valid) => (CoverageState::Covered, None),
            Some(verdict) => (
                CoverageState::CoveredUnverified,
                Some(format!(
                    "no signature covering this document verified; the best verdict among the {} covering signature(s) is {}",
                    covered_by.len(),
                    verdict.as_str()
                )),
            ),
            None => {
                // Nothing covers it. Something might have, had it been
                // evaluable — and "I could not tell" is not "nothing signs it".
                let blocked = sources.iter().find(|source| {
                    source.coverage.undetermined.is_some()
                        && containing_document(source.node, namespace)
                            .is_none_or(|document| document == node)
                });
                match blocked {
                    Some(source) => (
                        CoverageState::Undetermined,
                        Some(format!(
                            "a signature that might cover this document could not be evaluated: {}",
                            source.coverage.undetermined.unwrap_or_default()
                        )),
                    ),
                    None => (
                        CoverageState::Uncovered,
                        Some("no signature's resolved references include this document".to_owned()),
                    ),
                }
            }
        };
        if document.nested_dossier {
            // No implied recursion: an embedded dossier is payload here, and
            // this run says nothing at all about the signatures inside it.
            let note = "this document is an embedded dossier; it is covered like any other payload and its own inner signatures are not verified by this run";
            reason = Some(match reason {
                Some(text) => format!("{text}; {note}"),
                None => note.to_owned(),
            });
        }
        report.push(DocumentCoverage {
            index: Some(document.index),
            object_ref: Some(document.object_ref.clone()),
            nested_dossier: document.nested_dossier,
            coverage,
            covered_by,
            reason,
        });
    }
    report
}

fn coverage_count(documents: &[DocumentCoverage], state: CoverageState) -> usize {
    documents
        .iter()
        .filter(|document| document.coverage == state)
        .count()
}

/// The dossier-level checks the coverage report produces.
///
/// A verdict of `valid` has to mean that the whole dossier's content is
/// signed, so a modelled document nothing covers, or one whose coverage could
/// not be determined, is an open question and blocks with `unknown`. It is
/// never `failed`: an unsigned sibling is missing information about that
/// document, not evidence against any signature that did verify.
fn coverage_checks(documents: &[DocumentCoverage]) -> Vec<Check> {
    let mut checks = Vec::new();
    let uncovered: Vec<String> = documents
        .iter()
        .filter(|document| document.coverage == CoverageState::Uncovered)
        .filter_map(|document| document.index)
        .map(|index| index.to_string())
        .collect();
    let undetermined = coverage_count(documents, CoverageState::Undetermined);
    let unverified = coverage_count(documents, CoverageState::CoveredUnverified);
    let modelled = documents
        .iter()
        .filter(|document| document.coverage != CoverageState::NotModelled)
        .count();

    if uncovered.is_empty() && undetermined == 0 {
        checks.push(if unverified == 0 {
            Check::passed(
                CheckCode::DocumentsAllCovered,
                format!(
                    "every one of the {modelled} modelled document(s) is covered by a signature that verified"
                ),
            )
        } else {
            // Informational, and only because the finding is already
            // elsewhere: the covering signature's own verdict is not `valid`,
            // which has already capped the dossier verdict.
            Check::info(
                CheckCode::DocumentsAllCovered,
                format!(
                    "every one of the {modelled} modelled document(s) is covered, but {unverified} of them only by signatures that did not verify; those signatures' own verdicts carry the finding"
                ),
            )
        });
    }
    if !uncovered.is_empty() {
        checks.push(Check::unknown(
            CheckCode::DocumentsUncovered,
            format!(
                "{} of {modelled} modelled document(s) are covered by no signature; indexes: {}",
                uncovered.len(),
                uncovered.join(", ")
            ),
        ));
    }
    if undetermined > 0 {
        checks.push(Check::unknown(
            CheckCode::DocumentsCoverageUndetermined,
            format!(
                "the coverage of {undetermined} of the {modelled} modelled document(s) could not be determined"
            ),
        ));
    }
    checks
}

/// What was concluded about one chain's qualified status.
struct Qualification {
    qualified: Option<bool>,
    device: Option<bool>,
    service: Option<String>,
    check: Check,
}

/// Whether one trusted-list service identity covers a validated chain.
///
/// The three identity forms are not equally strong, and the difference is
/// deliberate rather than incidental:
///
/// - **`X509Certificate`** is the only form that carries a key, so it is the
///   only one that can say "this certificate *was issued by* the listed
///   service" — a verified signature, not a name match. It is also the only
///   form that becomes a trust anchor.
/// - **`X509SKI`** names a certificate by the `subjectKeyIdentifier` a CA
///   chose to write into it. It can only recognise a certificate already in
///   the validated chain; it proves nothing on its own and cannot establish an
///   issuing relationship.
/// - **`X509SubjectName`** is weaker still: a name. It is compared through
///   [`crate::certs::name_key`] — every attribute type and value, in order,
///   exactly as written — because this project implements no RFC 4518 name
///   preparation and a lenient string comparison is exactly the sort of thing
///   that quietly widens trust.
///
/// Both weak forms are read only because a real national list uses them, and
/// they can only decide `qualified` — a legal category — over a chain some
/// anchor has already validated cryptographically. Neither can grant trust.
fn identity_covers(
    identity: &trust::ServiceIdentity,
    path: &[ParsedCertificate],
) -> Option<&'static str> {
    match identity {
        trust::ServiceIdentity::Certificate(der) => {
            let listed = ParsedCertificate::from_der(der, CertificateSource::TrustList)?;
            path.iter()
                .any(|certificate| {
                    certificate.der == listed.der
                        || (certificate.issuer_der() == listed.subject_der()
                            && crate::certs::verify_issued_by(certificate, &listed))
                })
                .then_some("its X509Certificate identity")
        }
        trust::ServiceIdentity::SubjectKeyIdentifier(ski) => path
            .iter()
            .any(|certificate| certificate.subject_key_identifier().as_ref() == Some(ski))
            .then_some("its X509SKI identity, which names a certificate without supplying one"),
        trust::ServiceIdentity::SubjectName(key) => path
            .iter()
            .any(|certificate| certificate.subject_name_key() == *key)
            .then_some(
                "its X509SubjectName identity, matched attribute by attribute and weaker than a certificate identity",
            ),
    }
}

/// Decide the qualified status of one validated chain.
///
/// The determination is made over the **whole chain**, not over its anchor. In
/// a real trusted list the CA/QC service identities are the issuing CAs, which
/// are intermediates; the root above them is often present only in a
/// `--trust-store` directory, and sometimes is not listed at all. Asking only
/// the anchor therefore reports "not determined" for precisely the chains a
/// trusted list exists to describe.
///
/// So: a chain is qualified when some certificate in it **is**, or was
/// **issued by**, the service digital identity of a CA/QC service the list
/// records as granted at the validation time. "Issued by" is a verified
/// signature, not a name match, so nothing is gained by minting a certificate
/// that merely claims the right issuer. The `X509SKI` and `X509SubjectName`
/// identity forms recognise a chain certificate without being able to state an
/// issuing relationship; see [`identity_covers`].
///
/// The signer's own `QCStatements` may then contradict the list, and do when a
/// certificate issued after eIDAS applied carries the extension without
/// `QcCompliance`, or carries one that will not parse. A post-eIDAS
/// certificate with **no** `QCStatements` extension at all does not contradict
/// anything, and the determination rests on the trusted list alone, exactly as
/// it does for a pre-eIDAS certificate. That is the looser of the two readings
/// and it is deliberate: the trusted list is the authority on which CA may
/// issue qualified certificates, and an issuer that omitted an assertion has
/// not denied it.
///
/// The answer is `None`, never `false`, when no trusted list covers the chain:
/// "not determined" and "determined not to be qualified" are different
/// statements and the report keeps them apart.
fn qualification(
    services: &[trust::TrustServiceIdentity],
    path: &[ParsedCertificate],
    time: trust::UnixTime,
) -> Qualification {
    let mut matched: Option<(&trust::TrustServiceIdentity, &'static str)> = None;
    for service in services {
        if !service
            .service
            .granted_at(time, trustlist::ServiceType::CaQc)
        {
            continue;
        }
        if let Some(how) = identity_covers(&service.identity, path) {
            matched = Some((service, how));
            break;
        }
    }

    let Some((service, how)) = matched else {
        if services.is_empty() {
            return Qualification {
                qualified: None,
                device: None,
                service: None,
                check: Check::info(
                    CheckCode::CertificateQualifiedUnknown,
                    "no trusted list was consulted, so this chain's qualified status is not determined",
                ),
            };
        }
        return Qualification {
            qualified: Some(false),
            device: None,
            service: None,
            check: Check::info(
                CheckCode::CertificateNotQualified,
                "no certificate in the validated chain is, or was issued by, a trusted-list CA/QC service granted at the validation time",
            ),
        };
    };
    let record = &service.service;
    let service_name = record.service_name.clone();
    let named = service_name
        .as_deref()
        .map(|name| format!(" ({name})"))
        .unwrap_or_default();
    // Which status was honoured is part of the finding: an eIDAS `granted` and
    // a pre-eIDAS `accredited` or `undersupervision` are different statements,
    // and the second is honoured only for the historical window before eIDAS
    // applied.
    let status = record
        .status_name_at(time)
        .map(|status| format!(", recorded as {status} at the validation time"))
        .unwrap_or_default();

    let leaf = &path[0];
    let post_eidas = crate::certs::unix_time(leaf.certificate.tbs_certificate.validity.not_before)
        >= EIDAS_APPLICATION_DATE;
    let (contradicts, device) = match leaf.qc_statement_oids() {
        Ok(Some(oids)) => (
            !oids.contains(&crate::certs::OID_QC_COMPLIANCE),
            Some(oids.contains(&crate::certs::OID_QC_SSCD)),
        ),
        // No statement is not a denial; the list is the authority.
        Ok(None) => (false, None),
        // A malformed extension is not read past.
        Err(()) => (true, None),
    };
    if post_eidas && contradicts {
        return Qualification {
            qualified: Some(false),
            device,
            service: service_name,
            check: Check::info(
                CheckCode::CertificateNotQualified,
                format!(
                    "a trusted-list CA/QC service{named} covers this chain, but the signing certificate was issued after eIDAS applied and its QCStatements do not assert QcCompliance"
                ),
            ),
        };
    }
    Qualification {
        qualified: Some(true),
        device,
        service: service_name,
        check: Check::info(
            CheckCode::CertificateQualified,
            format!(
                "the validated chain is covered by a trusted-list CA/QC service{named} granted at the validation time through {how}{status}"
            ),
        ),
    }
}

fn count(signatures: &[SignatureReport], verdict: Verdict) -> usize {
    signatures
        .iter()
        .filter(|signature| signature.verdict == verdict)
        .count()
}
