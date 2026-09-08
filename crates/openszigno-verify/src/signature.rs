//! The per-signature driver: `ds:SignedInfo` parsing, the signature-level
//! algorithm policy, canonicalization of `ds:SignedInfo`, and verification of
//! `ds:SignatureValue` against the certificate that actually signed it.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;

use crate::c14n::{C14nAlgorithm, NodeSet};
use crate::certs::{CertificateSource, ParsedCertificate, dedup};
use crate::codes::{Check, CheckCode, CheckStatus, Verdict};
use crate::countersign::countersignature_binding;
use crate::dsig::{
    Context, attribute, decode_base64, direct_child, direct_children, id_of, inclusive_prefixes,
    text_of,
};
use crate::policy::{Digest, SignatureScheme, Transform};
use crate::references::{
    Reference, digest_reference, is_known_c14n, parse_reference, report_reference,
    resolve_reference,
};
use crate::report::{ReferenceReport, SignatureReport, SignatureRole, SignatureScope};
use crate::scope::{placement_of, reference_scope_check};
use crate::tsa::TimestampKind;
use crate::xades::{self, StageC, XadesProperties, stage_c_binding, stage_c_presence};

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

/// One timestamp token found in a signature, and the data it covers.
pub struct TimestampSource {
    pub kind: TimestampKind,
    pub token: Vec<u8>,
    /// The canonicalized octets the token's message imprint must match.
    pub imprint_input: Vec<u8>,
    /// Set when the timestamp uses a form this build does not implement, in
    /// which case it is reported as unchecked rather than verified.
    pub unsupported: Option<String>,
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
    let properties = xades::parse(signature);
    let mut header = Header {
        index,
        scope,
        parent_signature_index: match scope {
            SignatureScope::Countersignature => placement.enclosing_index,
            _ => None,
        },
        role: SignatureRole::Signature,
        countersigns: Vec::new(),
        document_index: document_index_of(context, signature),
        signature_id: id_of(signature).map(str::to_owned),
        signing_time: properties.signing_time.clone(),
    };
    let unsupported_nesting_parent = match scope {
        SignatureScope::Unknown => placement.enclosing_index,
        _ => None,
    };
    let claimed_signing_time = properties
        .signing_time
        .as_deref()
        .and_then(crate::trust::parse_rfc3339);

    // --- Stage A1: structure ------------------------------------------------
    let signed_info = direct_child(signature, XMLDSIG_NAMESPACE, "SignedInfo");
    let signature_value_node = direct_child(signature, XMLDSIG_NAMESPACE, "SignatureValue");
    let (Some(signed_info), Some(signature_value_node)) = (signed_info, signature_value_node)
    else {
        checks.push(Check::failed(
            CheckCode::SigStructureInvalid,
            "the signature is missing ds:SignedInfo or ds:SignatureValue",
        ));
        return finish(
            header.clone(),
            stage_c_presence(&properties),
            checks,
            references_report,
            None,
            Vec::new(),
            None,
            Vec::new(),
            claimed_signing_time,
            unsupported_nesting_parent,
        );
    };
    let c14n_node = direct_child(signed_info, XMLDSIG_NAMESPACE, "CanonicalizationMethod");
    let method_node = direct_child(signed_info, XMLDSIG_NAMESPACE, "SignatureMethod");
    let reference_nodes: Vec<Node<'_, '_>> =
        direct_children(signed_info, XMLDSIG_NAMESPACE, "Reference").collect();
    let (Some(c14n_node), Some(method_node)) = (c14n_node, method_node) else {
        checks.push(Check::failed(
            CheckCode::SigStructureInvalid,
            "ds:SignedInfo is missing its canonicalization or signature method",
        ));
        return finish(
            header.clone(),
            stage_c_presence(&properties),
            checks,
            references_report,
            None,
            Vec::new(),
            None,
            Vec::new(),
            claimed_signing_time,
            unsupported_nesting_parent,
        );
    };
    if reference_nodes.is_empty() {
        checks.push(Check::failed(
            CheckCode::SigStructureInvalid,
            "ds:SignedInfo contains no ds:Reference",
        ));
        return finish(
            header.clone(),
            stage_c_presence(&properties),
            checks,
            references_report,
            None,
            Vec::new(),
            None,
            Vec::new(),
            claimed_signing_time,
            unsupported_nesting_parent,
        );
    }
    if reference_nodes.len() > context.limits.max_references_per_signature {
        checks.push(Check::failed(
            CheckCode::SigStructureInvalid,
            format!(
                "the signature exceeds {} references",
                context.limits.max_references_per_signature
            ),
        ));
        return finish(
            header.clone(),
            stage_c_presence(&properties),
            checks,
            references_report,
            None,
            Vec::new(),
            None,
            Vec::new(),
            claimed_signing_time,
            unsupported_nesting_parent,
        );
    }
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

    // --- Stage A3: canonicalization method ----------------------------------
    let c14n_uri = attribute(c14n_node, "Algorithm")
        .unwrap_or_default()
        .to_owned();
    let signed_info_algorithm = C14nAlgorithm::from_uri(&c14n_uri);
    match signed_info_algorithm {
        Some(algorithm) => checks.push(Check::passed(
            CheckCode::C14nMethodAllowed,
            format!(
                "ds:SignedInfo uses the {} canonicalization algorithm",
                algorithm.short_name()
            ),
        )),
        None => checks.push(Check::failed(
            CheckCode::C14nUnsupported,
            "the ds:CanonicalizationMethod algorithm is not supported",
        )),
    }

    // --- Stage A4: signature algorithm --------------------------------------
    let method_uri = attribute(method_node, "Algorithm").unwrap_or_default();
    let scheme = SignatureScheme::from_signature_uri(method_uri)
        .filter(|scheme| !scheme.is_legacy() || context.allow_legacy_algorithms);
    match scheme {
        Some(scheme) if scheme.is_legacy() => checks.push(Check::unknown(
            CheckCode::AlgorithmLegacyAllowed,
            format!(
                "ds:SignatureMethod is {}, admitted only because legacy algorithms were allowed; its strength is not vouched for",
                scheme.as_str()
            ),
        )),
        Some(scheme) => checks.push(Check::passed(
            CheckCode::SignatureAlgorithmAllowed,
            format!("ds:SignatureMethod is {}", scheme.as_str()),
        )),
        None => checks.push(Check::failed(
            CheckCode::AlgorithmRejected,
            "the ds:SignatureMethod algorithm is outside the pinned allowlist",
        )),
    }

    // --- Stage A5 to A8: per-reference policy -------------------------------
    let references: Vec<Reference> = reference_nodes
        .iter()
        .enumerate()
        .map(|(position, node)| parse_reference(*node, position))
        .collect();

    let mut digest_ok = true;
    let mut digest_legacy = false;
    for reference in &references {
        match Digest::from_digest_uri(&reference.digest_uri) {
            None => digest_ok = false,
            Some(digest) if digest.is_legacy() => {
                if context.allow_legacy_algorithms {
                    digest_legacy = true;
                } else {
                    digest_ok = false;
                }
            }
            Some(_) => {}
        }
    }
    if !digest_ok {
        checks.push(Check::failed(
            CheckCode::AlgorithmRejected,
            "a ds:DigestMethod algorithm is outside the pinned allowlist",
        ));
    } else if digest_legacy {
        checks.push(Check::unknown(
            CheckCode::AlgorithmLegacyAllowed,
            "a ds:DigestMethod names SHA-1, admitted only because legacy algorithms were allowed; its strength is not vouched for",
        ));
    } else {
        checks.push(Check::passed(
            CheckCode::DigestAlgorithmAllowed,
            "every ds:DigestMethod is inside the pinned allowlist",
        ));
    }

    let mut transforms_ok = true;
    let mut c14n_supported = true;
    for reference in &references {
        if reference.transforms.len() > context.limits.max_transforms_per_reference {
            transforms_ok = false;
            continue;
        }
        for (uri, _) in &reference.transforms {
            if Transform::from_uri(uri).is_some() {
                continue;
            }
            // A known canonicalization algorithm this crate does not implement
            // is reported as unsupported, not as an attack.
            if is_known_c14n(uri) {
                c14n_supported = false;
            } else {
                transforms_ok = false;
            }
        }
    }
    if !c14n_supported {
        checks.push(Check::failed(
            CheckCode::C14nUnsupported,
            "a transform names a canonicalization algorithm this build does not implement",
        ));
    }
    if transforms_ok {
        checks.push(Check::passed(
            CheckCode::TransformsAllowed,
            "every transform is inside the allowlist",
        ));
    } else {
        checks.push(Check::failed(
            CheckCode::TransformNotAllowed,
            "a transform is outside the allowlist; XSLT and XPath are refused unconditionally",
        ));
    }

    let mut same_document = true;
    for reference in &references {
        if !(reference.uri.is_empty() || reference.uri.starts_with('#')) {
            same_document = false;
        }
    }
    if same_document {
        checks.push(Check::passed(
            CheckCode::ReferencesSameDocument,
            "every reference is same-document",
        ));
    } else {
        checks.push(Check::failed(
            CheckCode::ReferenceExternal,
            "a reference names a URI outside the document; no reference is ever dereferenced",
        ));
    }

    let mut resolved: Vec<Option<Node<'_, '_>>> = Vec::new();
    let mut all_resolve = true;
    for reference in &references {
        let node = resolve_reference(context, reference);
        if node.is_none() && same_document {
            all_resolve = false;
        }
        resolved.push(node);
    }
    if all_resolve {
        checks.push(Check::passed(
            CheckCode::ReferencesResolve,
            "every reference resolves to exactly one node in the validated ID space",
        ));
    } else {
        checks.push(Check::failed(
            CheckCode::ReferenceUnresolved,
            "a reference does not resolve to a node in the validated ID space",
        ));
    }

    // --- Stage A9: reference scope ------------------------------------------
    checks.push(reference_scope_check(
        context,
        signature,
        &placement,
        properties.qualifying_properties,
        &references,
        &resolved,
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

/// Collect the signature timestamps and canonicalize what each one covers.
///
/// A `xades:SignatureTimeStamp` covers the canonicalized `ds:SignatureValue`
/// **element**, not the Base64 text and not its digest. The canonicalization
/// algorithm is the one the timestamp element names, defaulting to inclusive
/// C14N as XAdES prescribes. The `Include` and `ReferenceInfo` forms select
/// other data and are not implemented, so a timestamp that uses one is
/// reported as unchecked rather than verified against the wrong bytes.
/// Whether a `xades:SignatureTimeStamp` selects data this build cannot compute
/// the imprint over, and why.
///
/// The implicit form — no data-selection child at all — covers the
/// `ds:SignatureValue` element, which is what XAdES prescribes for a signature
/// timestamp. The explicit `xades:Include` form (EN 319 132-1, XAdES 1.3.2 and
/// 1.4.1) is accepted for exactly the case where it says the same thing: every
/// `Include` is a same-document `#id` reference resolving, through the
/// validated ID space, to *this signature's own* `ds:SignatureValue`. The
/// `referencedData` attribute is not consulted, because for this target it
/// cannot change what is digested.
///
/// Any other target set — another element, a URI that does not resolve, an
/// external reference, or the `ReferenceInfo`, `HashDataInfo` and
/// `XMLTimeStamp` forms — is refused by name rather than digested over the
/// wrong bytes.
fn unsupported_form(
    context: &Context<'_, '_, '_>,
    timestamp: Node<'_, '_>,
    signature_value: Node<'_, '_>,
) -> Option<String> {
    for child in timestamp.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "ReferenceInfo" | "HashDataInfo" | "XMLTimeStamp" => {
                return Some(
                    "the timestamp selects its data with a form this build does not implement"
                        .to_owned(),
                );
            }
            "Include" => {
                let uri = attribute(child, "URI").unwrap_or_default();
                let Some(id) = uri.strip_prefix('#').filter(|id| !id.is_empty()) else {
                    return Some(
                        "the timestamp includes a URI that is not a same-document reference"
                            .to_owned(),
                    );
                };
                match context.ids.get(id) {
                    Some(node) if node.id() == signature_value.id() => {}
                    _ => {
                        return Some(
                            "the timestamp includes data other than this signature's ds:SignatureValue"
                                .to_owned(),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn collect_timestamps(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
    properties: &XadesProperties<'_, '_>,
) -> Vec<TimestampSource> {
    let Some(signature_value) = direct_child(signature, XMLDSIG_NAMESPACE, "SignatureValue") else {
        return Vec::new();
    };
    let mut sources = Vec::new();
    for node in properties
        .signature_timestamps
        .iter()
        .take(context.limits.max_timestamps_per_signature)
    {
        let unsupported = unsupported_form(context, *node, signature_value);

        let tokens: Vec<Vec<u8>> = xades::xades_children(*node, "EncapsulatedTimeStamp")
            .filter_map(|element| decode_base64(&text_of(element)))
            .take(2)
            .collect();
        let (token, unsupported) = match (tokens.len(), unsupported) {
            (_, Some(reason)) => (tokens.first().cloned().unwrap_or_default(), Some(reason)),
            (1, None) => (tokens[0].clone(), None),
            (0, None) => (
                Vec::new(),
                Some("the timestamp carries no decodable xades:EncapsulatedTimeStamp".to_owned()),
            ),
            (_, None) => (
                tokens[0].clone(),
                Some(
                    "the timestamp carries more than one token, which this build does not process"
                        .to_owned(),
                ),
            ),
        };

        let algorithm = xades::ds_child(*node, "CanonicalizationMethod")
            .and_then(|method| {
                attribute(method, "Algorithm").map(|uri| (method, C14nAlgorithm::from_uri(uri)))
            })
            .map_or(
                Some((C14nAlgorithm::Inclusive { comments: false }, Vec::new())),
                |(method, algorithm)| {
                    algorithm.map(|algorithm| (algorithm, inclusive_prefixes(method)))
                },
            );
        let (imprint_input, unsupported) = match algorithm {
            Some((algorithm, prefixes)) => {
                match context.backend.canonicalize(
                    context.source,
                    &NodeSet::subtree(signature_value),
                    algorithm,
                    &prefixes,
                ) {
                    Ok(octets) => (octets, unsupported),
                    Err(_) => (
                        Vec::new(),
                        unsupported.or(Some(
                            "the ds:SignatureValue could not be canonicalized for the timestamp"
                                .to_owned(),
                        )),
                    ),
                }
            }
            None => (
                Vec::new(),
                unsupported.or(Some(
                    "the timestamp names a canonicalization algorithm this build does not implement"
                        .to_owned(),
                )),
            ),
        };

        sources.push(TimestampSource {
            kind: TimestampKind::SignatureTimestamp,
            token,
            imprint_input,
            unsupported,
        });
    }
    sources
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
