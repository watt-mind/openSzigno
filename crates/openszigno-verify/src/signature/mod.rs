//! The per-signature driver: `ds:SignedInfo` parsing, the signature-level
//! algorithm policy, canonicalization of `ds:SignedInfo`, and verification of
//! `ds:SignatureValue` against the certificate that actually signed it.
//!
//! The module is split by what each part decides: `signed_info` reads
//! `ds:SignedInfo` and applies the signature-level algorithm policy, and
//! `collect` gathers the signature's timestamp tokens and the octets each
//! one must be checked against. What stays here is the driver, signer
//! selection, and verification of `ds:SignatureValue`.

mod collect;
mod signed_info;
mod structure;

pub use collect::TimestampSource;

use collect::collect_timestamps;

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;

use crate::c14n::NodeSet;
use crate::certs::{CertificateSource, ParsedCertificate, dedup};
use crate::codes::{Check, CheckCode, CheckStatus, Verdict};
use crate::countersign::countersignature_binding;
use crate::dsig::{
    Context, decode_base64, direct_child, direct_children, id_of, inclusive_prefixes, text_of,
};
use crate::policy::SignatureScheme;
use crate::references::{digest_reference, effective_node_sets, report_reference};
use crate::report::{ReferenceReport, SignatureReport, SignatureRole, SignatureScope};
use crate::scope::{placement_of, reference_scope_check};
use crate::xades::{self, StageC, stage_c_binding, stage_c_presence};

/// What the signature covers, and the certificates it offers.
pub struct SignatureOutcome {
    pub report: SignatureReport,
    pub signer: Option<ParsedCertificate>,
    pub extra_certificates: Vec<ParsedCertificate>,
    /// The timestamp tokens this signature carries, with the octets each one
    /// must be checked against already canonicalized.
    pub timestamps: Vec<TimestampSource>,
    /// The claimed `xades:SigningTime` in Unix seconds, for the ordering check
    /// against a token's `genTime`.
    pub claimed_signing_time: Option<crate::trust::UnixTime>,
    /// Set when this signature is nested inside another one in a shape this
    /// build does not support, and names the index of that enclosing
    /// signature. The caller records an informational
    /// `nested_signatures_unsupported` on it: an unsupported nested signature
    /// says nothing about the signature it was dropped into, so it must not
    /// touch that signature's verdict.
    pub unsupported_nesting_parent: Option<usize>,
}

/// The identity of one signature, carried through every early return.
#[derive(Clone)]
struct Header {
    index: usize,
    scope: SignatureScope,
    /// The index of the signature this one is embedded in, for a recognised
    /// `xades:CounterSignature`.
    parent_signature_index: Option<usize>,
    role: SignatureRole,
    /// Every signature whose `ds:SignatureValue` this signature's references
    /// resolve to, by index.
    countersigns: Vec<usize>,
    document_index: Option<usize>,
    signature_id: Option<String>,
    /// The claimed `xades:SigningTime`, RFC 3339 UTC.
    signing_time: Option<String>,
}

/// Run stages A, B, and C over one `ds:Signature`.
///
/// Stage D is added by the caller, which owns the trust source.
pub fn verify_signature(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
    index: usize,
) -> SignatureOutcome {
    let mut checks: Vec<Check> = Vec::new();
    let mut references_report: Vec<ReferenceReport> = Vec::new();

    let placement = placement_of(context, signature);
    let scope = placement.scope;
    let unsupported_nesting_parent = match scope {
        SignatureScope::Unknown => placement.enclosing_index,
        _ => None,
    };

    // --- Stage A1: structure ------------------------------------------------
    let structure = match signed_info::parse(context, signature) {
        Ok(structure) => structure,
        Err(check) => {
            // No reference was parsed, let alone resolved, so *which*
            // qualifying properties this signature covers is not a question
            // this run can answer. The properties are read for reporting only;
            // the signing-certificate binding is never evaluated on this path.
            let properties = xades::parse(signature);
            checks.push(check);
            return finish(
                header_of(context, signature, index, &placement, &properties),
                stage_c_presence(&properties),
                checks,
                references_report,
                None,
                Vec::new(),
                None,
                Vec::new(),
                claimed_signing_time(&properties),
                unsupported_nesting_parent,
            );
        }
    };
    let signed_info = structure.signed_info;
    let signature_value_node = structure.signature_value_node;
    let c14n_node = structure.c14n_node;
    checks.push(Check::passed(
        CheckCode::SigStructure,
        "signature structure is well formed",
    ));

    // --- Stage A2: placement ------------------------------------------------
    match scope {
        SignatureScope::Document => checks.push(Check::passed(
            CheckCode::SigPlacement,
            "the signature is placed on a document",
        )),
        SignatureScope::Dossier => checks.push(Check::passed(
            CheckCode::SigPlacement,
            "the signature is placed on the dossier frame",
        )),
        SignatureScope::Countersignature => checks.push(Check::passed(
            CheckCode::SigPlacement,
            format!(
                "the signature is an enveloped xades:CounterSignature of signature {}",
                placement.enclosing_index.unwrap_or_default()
            ),
        )),
        SignatureScope::Unknown => checks.push(Check::failed(
            CheckCode::SigPlacementInvalid,
            format!(
                "the signature is not at a placement the e-dossier format defines: {}",
                placement
                    .reason
                    .as_deref()
                    .unwrap_or("the placement is not one this build describes")
            ),
        )),
    }

    // --- Stage A3 to A8: the signature-level algorithm policy ---------------
    let signed_info::Policy {
        signed_info_algorithm,
        scheme,
        references,
        resolved,
    } = signed_info::algorithm_policy(context, &structure, &mut checks);

    // What each reference actually digests, computed once: the scope rule, the
    // XAdES property selection below and the countersignature binding all
    // decide coverage from it, so they cannot disagree.
    let scopes = effective_node_sets(signature, &references, &resolved);

    // --- Stage C's input: the qualifying properties this signature covers ---
    // Selected by coverage rather than by document position, because a
    // `ds:Object` is open content: an inserted, unreferenced one must not be
    // able to decide what stage C reads.
    let properties = xades::parse_covered(signature, &scopes);
    let mut header = header_of(context, signature, index, &placement, &properties);
    let claimed_signing_time = claimed_signing_time(&properties);

    // --- Stage A9: reference scope ------------------------------------------
    checks.push(reference_scope_check(
        context,
        signature,
        &placement,
        properties.qualifying_properties,
        &references,
        &scopes,
    ));

    // --- Stage A10: the countersignature binding ----------------------------
    // What a countersignature attests is *another signature's value*, so the
    // binding is a policy question about the reference set and belongs here,
    // beside the scope rule, not in the cryptographic stage.
    let binding = countersignature_binding(context, signature, &placement, &references, &resolved);
    header.role = binding.role;
    header.countersigns = binding.countersigns;
    if let Some(check) = binding.check {
        checks.push(check);
    }

    let policy_failed = checks
        .iter()
        .any(|check| check.status == CheckStatus::Failed);

    // --- Stage B ------------------------------------------------------------
    let mut signer = None;
    let mut signer_index = None;
    let mut extra_certificates = Vec::new();
    let mut key_info_candidates: Vec<ParsedCertificate> = Vec::new();
    let mut reached_stage_b = false;
    let mut timestamps: Vec<TimestampSource> = Vec::new();
    if policy_failed {
        // The resolution stage already knows what every URI pointed at, and a
        // caller needs to see that even when the run stopped before any digest
        // was recomputed.
        for (reference, node) in references.iter().zip(resolved.iter()) {
            references_report.push(report_reference(reference, *node, CheckStatus::Skipped));
        }
    } else {
        let mut digests_matched = 0usize;
        let mut digest_failed = false;
        for (reference, node) in references.iter().zip(resolved.iter()) {
            let node = node.expect("every reference resolved");
            let status = match digest_reference(context, signature, reference, node) {
                Ok(true) => {
                    digests_matched += 1;
                    CheckStatus::Passed
                }
                Ok(false) => {
                    digest_failed = true;
                    CheckStatus::Failed
                }
                Err(()) => {
                    digest_failed = true;
                    CheckStatus::Failed
                }
            };
            references_report.push(report_reference(reference, Some(node), status));
        }
        if digest_failed {
            checks.push(Check::failed(
                CheckCode::ReferenceDigestMismatch,
                format!(
                    "{digests_matched} of {} reference digests matched",
                    references.len()
                ),
            ));
        } else {
            checks.push(Check::passed(
                CheckCode::ReferenceDigestOk,
                format!(
                    "{digests_matched} of {} reference digests matched",
                    references.len()
                ),
            ));
        }

        let algorithm = signed_info_algorithm.expect("the algorithm was accepted above");
        let signed_info_set = NodeSet::subtree(signed_info);
        let canonical = context.backend.canonicalize(
            context.source,
            &signed_info_set,
            algorithm,
            &inclusive_prefixes(c14n_node),
        );
        match canonical {
            Ok(canonical) => {
                checks.push(Check::passed(
                    CheckCode::SignedInfoCanonicalization,
                    "ds:SignedInfo canonicalized without error",
                ));
                reached_stage_b = true;
                let candidates = dedup(key_info_certificates(signature));
                key_info_candidates = candidates.clone();
                timestamps = collect_timestamps(context, signature, &properties);
                extra_certificates = candidates.clone();
                extra_certificates.extend(encapsulated_certificates(
                    signature,
                    context.limits.max_certificates,
                ));
                extra_certificates = dedup(extra_certificates);
                if candidates.is_empty() {
                    checks.push(Check::failed(
                        CheckCode::SigningCertificateMissing,
                        "no usable certificate was found in ds:KeyInfo",
                    ));
                } else {
                    let scheme = scheme.expect("the scheme was accepted above");
                    match decode_base64(&text_of(signature_value_node)) {
                        None => {
                            signer = candidates.first().cloned();
                            checks.push(Check::passed(
                                CheckCode::SigningCertificateAvailable,
                                format!(
                                    "{} certificate(s) in ds:KeyInfo were offered as the signer",
                                    candidates.len()
                                ),
                            ));
                            checks.push(Check::failed(
                                CheckCode::SignatureValueInvalid,
                                "ds:SignatureValue is not canonical Base64",
                            ));
                        }
                        Some(bytes) => {
                            match select_signer(&candidates, scheme, &canonical, &bytes) {
                                Ok(index) => {
                                    signer = Some(candidates[index].clone());
                                    signer_index = Some(index);
                                    checks.push(Check::passed(
                                        CheckCode::SigningCertificateAvailable,
                                        format!(
                                            "certificate {} of {} in ds:KeyInfo verifies the signature",
                                            index + 1,
                                            candidates.len()
                                        ),
                                    ));
                                    checks.push(Check::passed(
                                        CheckCode::SignatureValueOk,
                                        "the signature value verified over the canonical ds:SignedInfo",
                                    ));
                                }
                                Err(error) => {
                                    signer = candidates.first().cloned();
                                    checks.push(Check::passed(
                                        CheckCode::SigningCertificateAvailable,
                                        format!(
                                            "{} certificate(s) in ds:KeyInfo were offered as the signer",
                                            candidates.len()
                                        ),
                                    ));
                                    match error {
                                        crate::certs::VerifyError::WeakKey => {
                                            checks.push(Check::failed(
                                                CheckCode::AlgorithmRejected,
                                                "the signing key is below the minimum accepted size",
                                            ));
                                        }
                                        crate::certs::VerifyError::UnsupportedKey => {
                                            checks.push(Check::failed(
                                                CheckCode::AlgorithmRejected,
                                                "the signing key type does not match the signature method",
                                            ));
                                        }
                                        _ => checks.push(Check::failed(
                                            CheckCode::SignatureValueInvalid,
                                            format!(
                                                "the signature value did not verify against any of the {} certificate(s) in ds:KeyInfo",
                                                candidates.len()
                                            ),
                                        )),
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => checks.push(Check::failed(
                CheckCode::SignedInfoCanonicalizationFailed,
                "ds:SignedInfo could not be canonicalized",
            )),
        }
    }

    let stage_c = if reached_stage_b {
        stage_c_binding(
            &properties,
            &key_info_candidates,
            signer_index,
            context.allow_legacy_algorithms,
            timestamps.len(),
        )
    } else {
        stage_c_presence(&properties)
    };
    // The *signed* SigningCertificate decides which certificate the signature
    // claims, so a disagreement with the key-based selection moves the signer
    // as well as failing the check: the path is then validated for the
    // certificate the signature actually designates.
    if let Some(position) = stage_c.signer_override
        && let Some(certificate) = key_info_candidates.get(position)
    {
        signer = Some(certificate.clone());
        signer_index = Some(position);
    }

    finish(
        header,
        stage_c,
        checks,
        references_report,
        signer,
        extra_certificates,
        signer_index,
        timestamps,
        claimed_signing_time,
        unsupported_nesting_parent,
    )
}

/// The identity of one signature, from its placement and the properties this
/// run decided it is evaluated against.
fn header_of(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
    index: usize,
    placement: &crate::scope::Placement<'_, '_>,
    properties: &xades::XadesProperties<'_, '_>,
) -> Header {
    Header {
        index,
        scope: placement.scope,
        parent_signature_index: match placement.scope {
            SignatureScope::Countersignature => placement.enclosing_index,
            _ => None,
        },
        role: SignatureRole::Signature,
        countersigns: Vec::new(),
        document_index: document_index_of(context, signature),
        signature_id: id_of(signature).map(str::to_owned),
        signing_time: properties.signing_time.clone(),
    }
}

fn claimed_signing_time(
    properties: &xades::XadesProperties<'_, '_>,
) -> Option<crate::trust::UnixTime> {
    properties
        .signing_time
        .as_deref()
        .and_then(crate::trust::parse_rfc3339)
}

#[allow(clippy::too_many_arguments)]
fn finish(
    header: Header,
    stage_c: StageC,
    mut checks: Vec<Check>,
    references: Vec<ReferenceReport>,
    signer: Option<ParsedCertificate>,
    extra_certificates: Vec<ParsedCertificate>,
    signer_index: Option<usize>,
    timestamps: Vec<TimestampSource>,
    claimed_signing_time: Option<crate::trust::UnixTime>,
    unsupported_nesting_parent: Option<usize>,
) -> SignatureOutcome {
    checks.extend(stage_c.checks);
    // The claimed signing time is read and reported, never believed: it is a
    // claim until a verified timestamp token orders it, and it never becomes a
    // validation time.
    // Informational on purpose: a claimed signing time is unauthenticated
    // whether it is there or not, so its presence decides nothing. What does
    // decide is the validation time, which only `--at`, a verified timestamp,
    // and the clock can set.
    match &header.signing_time {
        Some(_) => checks.push(Check::info(
            CheckCode::SigningTimePresent,
            "a claimed xades:SigningTime was read; it is unauthenticated and is never used as a validation time",
        )),
        None => checks.push(Check::info(
            CheckCode::SigningTimePresent,
            "no usable xades:SigningTime was found",
        )),
    }

    SignatureOutcome {
        report: SignatureReport {
            index: header.index,
            scope: header.scope,
            placement: header.scope,
            role: header.role,
            parent_signature_index: header.parent_signature_index,
            countersigns: header.countersigns,
            document_index: header.document_index,
            signature_id: header.signature_id,
            verdict: Verdict::Indeterminate,
            xades_level: stage_c.report.present.then_some("detected"),
            signing_time: header.signing_time,
            signing_certificate_index: signer_index,
            signing_certificate: signer.as_ref().map(ParsedCertificate::summary),
            qualified: None,
            qualified_signature_device: None,
            qualified_service: None,
            chain: Vec::new(),
            references,
            xades: stage_c.report,
            timestamps: Vec::new(),
            validation_time: String::new(),
            validation_time_source: crate::report::ValidationTimeSource::CurrentTime,
            checks,
        },
        signer,
        extra_certificates,
        timestamps,
        claimed_signing_time,
        unsupported_nesting_parent,
    }
}

/// The index the structural model gives the containing document, which counts
/// only documents that carry a `DocumentProfile`.
fn document_index_of(context: &Context<'_, '_, '_>, signature: Node<'_, '_>) -> Option<usize> {
    let document = signature.parent()?;
    if document.tag_name().namespace() != Some(context.namespace)
        || document.tag_name().name() != "Document"
    {
        return None;
    }
    direct_child(document, context.namespace, "DocumentProfile")?;
    let documents = document.parent()?;
    Some(
        direct_children(documents, context.namespace, "Document")
            .take_while(|candidate| candidate.id() != document.id())
            .filter(|candidate| {
                direct_child(*candidate, context.namespace, "DocumentProfile").is_some()
            })
            .count(),
    )
}

/// The certificates `ds:KeyInfo` offers, in document order.
///
/// Bounded, because `ds:KeyInfo` is attacker-controlled and every one of these
/// is tried as a signing-certificate candidate.
const MAX_KEY_INFO_CERTIFICATES: usize = 16;

fn key_info_certificates(signature: Node<'_, '_>) -> Vec<ParsedCertificate> {
    let Some(key_info) = direct_child(signature, XMLDSIG_NAMESPACE, "KeyInfo") else {
        return Vec::new();
    };
    key_info
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XMLDSIG_NAMESPACE)
                && node.tag_name().name() == "X509Certificate"
        })
        .filter_map(|node| decode_base64(&text_of(node)))
        .filter_map(|der| ParsedCertificate::from_der(&der, CertificateSource::KeyInfo))
        .take(MAX_KEY_INFO_CERTIFICATES)
        .collect()
}

/// Every certificate encapsulated in the signature's XAdES properties.
///
/// Real dossiers put only the signer in `ds:KeyInfo` and carry the
/// intermediates — and usually the root — in
/// `xades:CertificateValues/xades:EncapsulatedX509Certificate`, and long-term
/// material repeats them inside `xades141:TimeStampValidationData`. Both
/// placements are harvested, and inside either container the element is matched
/// by name alone, because real dossiers mix the 1.3.2 and 1.4.1 namespaces
/// within one block.
///
/// These are **untrusted path candidates**: a self-signed root found here is
/// still not an anchor, and only the trust store or a trusted list can make
/// one.
fn encapsulated_certificates(signature: Node<'_, '_>, limit: usize) -> Vec<ParsedCertificate> {
    let mut certificates = Vec::new();
    for container in xades::validation_data_containers(signature) {
        for node in container.descendants().filter(|node| {
            node.is_element() && node.tag_name().name() == "EncapsulatedX509Certificate"
        }) {
            if certificates.len() >= limit {
                return certificates;
            }
            if let Some(certificate) = decode_base64(&text_of(node)).and_then(|der| {
                ParsedCertificate::from_der(&der, CertificateSource::CertificateValues)
            }) && !certificates
                .iter()
                .any(|existing: &ParsedCertificate| existing.der == certificate.der)
            {
                certificates.push(certificate);
            }
        }
    }
    certificates
}

/// Choose the signing certificate: the candidate whose public key actually
/// verifies `ds:SignatureValue`.
///
/// XMLDSig imposes no order on `ds:KeyInfo`, and real material does list an
/// issuer before the signer, so taking the first certificate would turn a good
/// signature into a false failure. End-entity certificates are tried first so
/// that the common case costs one verification.
fn select_signer(
    candidates: &[ParsedCertificate],
    scheme: SignatureScheme,
    canonical: &[u8],
    signature_value: &[u8],
) -> Result<usize, crate::certs::VerifyError> {
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by_key(|index| u8::from(candidates[*index].is_certificate_authority()));
    let mut worst = crate::certs::VerifyError::BadSignature;
    for index in order {
        match crate::certs::verify_with_spki(
            &candidates[index].certificate,
            scheme,
            canonical,
            signature_value,
            false,
        ) {
            Ok(()) => return Ok(index),
            // A weak or unusable key is a policy answer, not just a mismatch,
            // and is reported when nothing verifies.
            Err(
                error @ (crate::certs::VerifyError::WeakKey
                | crate::certs::VerifyError::UnsupportedKey),
            ) => worst = error,
            Err(_) => {}
        }
    }
    Err(worst)
}
