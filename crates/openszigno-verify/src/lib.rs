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
    SignatureReport, SignatureScope, SigningCertificateBinding, ValidationTimeSource, VerifyReport,
    XadesReport,
};
pub use revocation::{CertificateRevocation, RevocationOrigin, RevocationStatus};
pub use trust::{
    Clock, FixedClock, MemoryRevocationStore, MemoryTrustStore, NoRevocation, NoTrust,
    RevocationPolicy, RevocationSource, SystemClock, TrustAnchor, TrustAnchorOrigin, TrustSource,
    format_rfc3339, parse_rfc3339,
};
pub use trustlist::{ServiceRecord, ServiceType, TrustList};
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
    let mut services: Vec<(ParsedCertificate, &trust::TrustAnchor)> = Vec::new();
    for anchor in options.trust.anchors() {
        let source = match anchor.origin {
            trust::TrustAnchorOrigin::TrustList => CertificateSource::TrustList,
            trust::TrustAnchorOrigin::TrustStore => CertificateSource::TrustStore,
        };
        let Some(parsed) = ParsedCertificate::from_der(&anchor.der, source) else {
            continue;
        };
        if anchor.service.is_some() {
            services.push((parsed.clone(), anchor));
        }
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
        let revocation_data = revocation::RevocationData {
            embedded_crls: &embedded_crls,
            embedded_ocsp: &embedded_ocsp,
            store_crls: options.revocation.crls(),
            store_ocsp: options.revocation.ocsp_responses(),
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
                let listed = services.iter().any(|(certificate, _)| {
                    certificate.der == anchor.der
                        && certificate.source == CertificateSource::TrustList
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
                let outcome = qualification(&services, &path.path, signature_time);
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
                    trust::RevocationPolicy::Offline => Check::unknown(
                        CheckCode::RevocationStatusUnknown,
                        "no validated certification path was available, so revocation could not be checked",
                    ),
                });
            } else {
                let outcome = revocation::check_path(&revocation::PathRevocationInput {
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

    if dossier.timestamps_present > 0 {
        // A dossier-level `es:TimeStamp` protects the elements it references,
        // so verifying one needs the reference machinery M3 adds. Reporting it
        // as unchecked is the honest answer; guessing at what it covers and
        // then reporting a match would not be.
        //
        // Informational, and at the dossier level only: an `es:TimeStamp` is a
        // statement about the container, not about any one signature, so it
        // must not decide whether the signatures inside it are valid. A
        // consumer that needs the container's own time attested reads this
        // check; a consumer asking whether a signature verified does not.
        dossier_checks.push(Check::info(
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
        policy: PolicyReport::new(
            options.trust.configured(),
            options.allow_legacy_algorithms,
            revocation_policy,
        ),
        limits: options.limits.clone(),
        counts,
        checks: dossier_checks,
        signatures,
    })
}

/// When eIDAS (Regulation (EU) 910/2014) began to apply, which is the line
/// after which a qualified certificate must carry `QcCompliance` itself.
/// Before it, the trusted list's own record is the whole story, because the
/// statement had not been mandated yet.
const EIDAS_APPLICATION_DATE: trust::UnixTime = 1_467_324_000; // 2016-07-01T00:00:00Z

/// What was concluded about one chain's qualified status.
struct Qualification {
    qualified: Option<bool>,
    device: Option<bool>,
    service: Option<String>,
    check: Check,
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
/// that merely claims the right issuer.
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
    services: &[(ParsedCertificate, &trust::TrustAnchor)],
    path: &[ParsedCertificate],
    time: trust::UnixTime,
) -> Qualification {
    let mut listed = false;
    let mut matched: Option<(&ParsedCertificate, &trustlist::ServiceRecord)> = None;
    for (identity, anchor) in services {
        let Some(record) = anchor.service.as_ref() else {
            continue;
        };
        listed = true;
        if !record.granted_at(time, trustlist::ServiceType::CaQc) {
            continue;
        }
        let covers = path.iter().any(|certificate| {
            certificate.der == identity.der
                || (certificate.issuer_der() == identity.subject_der()
                    && crate::certs::verify_issued_by(certificate, identity))
        });
        if covers {
            matched = Some((identity, record));
            break;
        }
    }

    let Some((identity, record)) = matched else {
        if !listed {
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
    let service_name = record
        .service_name
        .clone()
        .or_else(|| crate::certs::common_name(&identity.certificate.tbs_certificate.subject));
    let named = service_name
        .as_deref()
        .map(|name| format!(" ({name})"))
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
                "the validated chain is covered by a trusted-list CA/QC service{named} granted at the validation time"
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
