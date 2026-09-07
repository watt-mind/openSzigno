//! The XMLDSig core: `ds:SignedInfo`, references, transforms, and the
//! signature value.
//!
//! Reference resolution is strictly same-document and goes through the ID space
//! `openszigno-core` validated, so a duplicate ID is already a parse error and
//! no reference can ever resolve ambiguously or reach the network or the
//! filesystem.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::{Node, NodeId};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::c14n::{C14nAlgorithm, C14nBackend, EXC_C14N_NAMESPACE, NodeSet};
use crate::certs::{CertificateSource, ParsedCertificate, dedup};
use crate::codes::{Check, CheckCode, CheckStatus, Verdict, verdict_of};
use crate::policy::{Digest, SignatureScheme, Transform, VerifyLimits};
use crate::report::{ReferenceReport, SignatureReport, SignatureScope, XadesReport};
use crate::tsa::TimestampKind;
use crate::xades::{self, BindingFailure, SignaturePolicy, XadesProperties};

/// The XAdES namespaces seen in e-dossiers: 1.3.2 in current material, 1.2.2
/// and 1.1.1 in legacy material, 1.4.1 for the archival extensions.
pub const XADES_NAMESPACES: &[&str] = &[
    "http://uri.etsi.org/01903/v1.3.2#",
    "http://uri.etsi.org/01903/v1.2.2#",
    "http://uri.etsi.org/01903/v1.1.1#",
    "http://uri.etsi.org/01903/v1.4.1#",
];

/// `ds:Reference/@Type` values that announce a `SignedProperties` reference.
///
/// These are corroboration only. Coverage is decided by *what a reference
/// resolves to*, never by what its `Type` attribute claims, because a `Type`
/// an attacker controls must not be able to satisfy a scope requirement, and
/// legacy XAdES 1.2.2 material uses the versioned URI.
const SIGNED_PROPERTIES_TYPES: &[&str] = &[
    "http://uri.etsi.org/01903#SignedProperties",
    "http://uri.etsi.org/01903/v1.1.1#SignedProperties",
    "http://uri.etsi.org/01903/v1.2.2#SignedProperties",
    "http://uri.etsi.org/01903/v1.3.2#SignedProperties",
    "http://uri.etsi.org/01903/v1.4.1#SignedProperties",
];

/// Everything one signature needs, gathered once for the whole dossier.
pub struct Context<'a, 'input, 's> {
    pub source: &'s str,
    pub root: Node<'a, 'input>,
    pub ids: &'a BTreeMap<&'a str, Node<'a, 'input>>,
    pub namespace: &'a str,
    /// Every dossier namespace the caller allows, so an `es:SignatureProfile`
    /// is recognised whichever compatible profile declared it.
    pub allowed_namespaces: &'a [String],
    pub backend: &'a dyn C14nBackend,
    pub limits: &'a VerifyLimits,
    /// Whether `--allow-legacy-algorithms` admits SHA-1 for diagnosis.
    pub allow_legacy_algorithms: bool,
}

/// The parsed shape of one `ds:Reference`.
struct Reference {
    index: usize,
    uri: String,
    reference_type: Option<String>,
    transforms: Vec<(String, Vec<String>)>,
    digest_uri: String,
    digest_value: String,
}

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
    document_index: Option<usize>,
    signature_id: Option<String>,
    /// The claimed `xades:SigningTime`, RFC 3339 UTC.
    signing_time: Option<String>,
}

/// The outcome of stage C, gathered before the report is assembled.
struct StageC {
    checks: Vec<Check>,
    report: XadesReport,
    /// The `ds:KeyInfo` candidate the signed `SigningCertificate` designates,
    /// which overrides the key-based selection when the two disagree.
    signer_override: Option<usize>,
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

    let scope = placement_of(context, signature);
    let properties = xades::parse(signature);
    let header = Header {
        index,
        scope,
        document_index: document_index_of(context, signature),
        signature_id: id_of(signature).map(str::to_owned),
        signing_time: properties.signing_time.clone(),
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
            header,
            stage_c_presence(&properties),
            checks,
            references_report,
            None,
            Vec::new(),
            None,
            Vec::new(),
            claimed_signing_time,
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
            header,
            stage_c_presence(&properties),
            checks,
            references_report,
            None,
            Vec::new(),
            None,
            Vec::new(),
            claimed_signing_time,
        );
    };
    if reference_nodes.is_empty() {
        checks.push(Check::failed(
            CheckCode::SigStructureInvalid,
            "ds:SignedInfo contains no ds:Reference",
        ));
        return finish(
            header,
            stage_c_presence(&properties),
            checks,
            references_report,
            None,
            Vec::new(),
            None,
            Vec::new(),
            claimed_signing_time,
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
            header,
            stage_c_presence(&properties),
            checks,
            references_report,
            None,
            Vec::new(),
            None,
            Vec::new(),
            claimed_signing_time,
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
        SignatureScope::Unknown => checks.push(Check::failed(
            CheckCode::SigPlacementInvalid,
            "the signature is not at a placement the e-dossier format defines",
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
        let node = if reference.uri.is_empty() {
            Some(context.root)
        } else if let Some(id) = reference.uri.strip_prefix('#') {
            context.ids.get(id).copied()
        } else {
            None
        };
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
        scope,
        properties.qualifying_properties,
        &references,
        &resolved,
    ));

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
    }
}

/// The part of stage C that needs no cryptography: what the properties are,
/// and what this build did not process.
///
/// Used on its own when the signature failed an earlier stage, because the
/// signing-certificate binding cannot be evaluated against a signature whose
/// references were never resolved.
fn stage_c_presence(properties: &XadesProperties<'_, '_>) -> StageC {
    let mut checks = Vec::new();
    let present = properties.qualifying_properties.is_some();
    if present {
        checks.push(Check::passed(
            CheckCode::XadesPresent,
            "XAdES qualifying properties are present",
        ));
    } else {
        checks.push(Check::skipped(
            CheckCode::XadesAbsent,
            "no XAdES qualifying properties were found for this signature",
        ));
    }

    // A signature policy is reported by identifier only: no policy document is
    // fetched, parsed, or applied, so neither form can contribute a `passed`.
    // Informational: a declared policy is a statement about how the signature
    // was made, not a question this build failed to answer. Blocking on it
    // would cap every policy-bearing signature at `indeterminate` for a
    // property that says nothing about whether the signature is sound.
    match properties.signature_policy {
        Some(SignaturePolicy::Implied) => checks.push(Check::info(
            CheckCode::XadesSignaturePolicyImplied,
            "the signature declares an implied signature policy; no policy is processed",
        )),
        Some(SignaturePolicy::Explicit) => checks.push(Check::info(
            CheckCode::XadesSignaturePolicyExplicit,
            "the signature declares an explicit signature policy; its identifier is reported and no policy is processed",
        )),
        None => {}
    }

    if !properties.unprocessed_properties.is_empty() {
        checks.push(Check::skipped(
            CheckCode::XadesNotValidated,
            format!(
                "qualifying properties this build does not validate are present: {}",
                properties.unprocessed_properties.join(", ")
            ),
        ));
    }
    if properties.archive_timestamps > 0 {
        checks.push(Check::skipped(
            CheckCode::ArchiveTimestampPresent,
            "an xades:ArchiveTimeStamp is present; archive timestamps are out of scope for this release",
        ));
    }

    StageC {
        checks,
        report: XadesReport {
            present,
            signing_time: properties.signing_time.clone(),
            signing_certificate: None,
            signature_policy: properties.signature_policy,
            signature_policy_id: properties.signature_policy_id.clone(),
            signature_timestamps: properties.signature_timestamps.len(),
            archive_timestamps: properties.archive_timestamps,
            unvalidated_properties: properties.unprocessed_properties.clone(),
        },
        signer_override: None,
    }
}

/// Stage C in full: the signed `SigningCertificate` binding on top of the
/// presence reporting.
///
/// This is the substitution check. `ds:KeyInfo` is unsigned unless a reference
/// covers it, so the certificate the signature *claims* is the one the signed
/// `CertDigest` names. When the certificate whose key verified the signature is
/// not that one, the check fails: someone swapped the certificate.
fn stage_c_binding(
    properties: &XadesProperties<'_, '_>,
    candidates: &[ParsedCertificate],
    key_signer_index: Option<usize>,
    allow_legacy_algorithms: bool,
    signature_timestamps: usize,
) -> StageC {
    let mut stage = stage_c_presence(properties);
    let _ = signature_timestamps;
    if properties.certificate_references.is_empty() {
        stage.checks.push(Check::unknown(
            CheckCode::XadesSigningCertificateAbsent,
            "the signature carries no xades:SigningCertificate, so nothing signed says which certificate signed it",
        ));
        return stage;
    }
    let form = properties.signing_certificate_form;
    match xades::match_certificate(
        &properties.certificate_references,
        candidates,
        allow_legacy_algorithms,
    ) {
        Ok(position) => {
            let bound = key_signer_index.is_none_or(|index| index == position);
            if bound {
                stage.checks.push(Check::passed(
                    CheckCode::XadesSigningCertificateBound,
                    "the signing certificate matches the digest the signed SigningCertificate property names",
                ));
            } else {
                stage.checks.push(Check::failed(
                    CheckCode::XadesSigningCertificateMismatch,
                    "the certificate whose key verified the signature is not the one the signed SigningCertificate property names",
                ));
            }
            stage.signer_override = Some(position);
            stage.report.signing_certificate = Some(crate::report::SigningCertificateBinding {
                form,
                digest_algorithm: properties
                    .certificate_references
                    .first()
                    .and_then(|reference| {
                        Digest::from_digest_uri(&reference.digest_uri).map(Digest::as_str)
                    }),
                issuer_serial_present: properties.certificate_references.iter().any(|reference| {
                    reference.issuer_serial.is_some() || reference.issuer_serial_v2.is_some()
                }),
                matched: true,
            });
        }
        Err(failure) => {
            let message = match failure {
                BindingFailure::DigestAlgorithm => {
                    "the SigningCertificate property names no digest algorithm inside the pinned allowlist"
                }
                BindingFailure::IssuerSerial => {
                    "a certificate digests to the SigningCertificate property but its issuer and serial do not match"
                }
                BindingFailure::NoMatch => {
                    "no offered certificate digests to the certificate the signed SigningCertificate property names"
                }
            };
            stage.checks.push(Check::failed(
                CheckCode::XadesSigningCertificateMismatch,
                message,
            ));
            stage.report.signing_certificate = Some(crate::report::SigningCertificateBinding {
                form,
                digest_algorithm: properties
                    .certificate_references
                    .first()
                    .and_then(|reference| {
                        Digest::from_digest_uri(&reference.digest_uri).map(Digest::as_str)
                    }),
                issuer_serial_present: properties.certificate_references.iter().any(|reference| {
                    reference.issuer_serial.is_some() || reference.issuer_serial_v2.is_some()
                }),
                matched: false,
            });
        }
    }
    stage
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

/// Recompute one reference digest.
///
/// `Ok(false)` is a mismatch; `Err(())` is a transform or canonicalization
/// failure, which is treated as a mismatch by the caller because an
/// unprocessable reference is not a verified one.
fn digest_reference(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
    reference: &Reference,
    node: Node<'_, '_>,
) -> Result<bool, ()> {
    enum Value<'a, 'input> {
        Nodes(NodeSet<'a, 'input>),
        Bytes(Vec<u8>),
    }

    // XMLDSig 4.4.3.3: a same-document reference dereferences to a node-set
    // that has already had its comments removed, so a with-comments transform
    // applied afterwards still sees none.
    let mut value = Value::Nodes(
        if node.is_root() {
            NodeSet::document(node)
        } else {
            NodeSet::subtree(node)
        }
        .without_comments(),
    );

    for (uri, prefixes) in &reference.transforms {
        let transform = Transform::from_uri(uri).ok_or(())?;
        value = match (transform, value) {
            (Transform::EnvelopedSignature, Value::Nodes(mut set)) => {
                set.exclude(signature);
                Value::Nodes(set)
            }
            (Transform::Canonicalization(algorithm), Value::Nodes(set)) => Value::Bytes(
                context
                    .backend
                    .canonicalize(context.source, &set, algorithm, prefixes)
                    .map_err(|_| ())?,
            ),
            (Transform::Base64, Value::Nodes(set)) => {
                Value::Bytes(decode_base64(&set.string_value()).ok_or(())?)
            }
            (Transform::Base64, Value::Bytes(bytes)) => {
                Value::Bytes(decode_base64(std::str::from_utf8(&bytes).map_err(|_| ())?).ok_or(())?)
            }
            // A node-set transform after the octet stream has been produced is
            // not something this profile allows.
            (_, Value::Bytes(_)) => return Err(()),
        };
    }

    let octets = match value {
        Value::Bytes(bytes) => bytes,
        // XMLDSig applies the default canonicalization when a reference ends as
        // a node-set.
        Value::Nodes(set) => context
            .backend
            .canonicalize(
                context.source,
                &set,
                C14nAlgorithm::Inclusive { comments: false },
                &[],
            )
            .map_err(|_| ())?,
    };

    let digest = Digest::from_digest_uri(&reference.digest_uri).ok_or(())?;
    let computed = match digest {
        Digest::Sha1 => sha1::Sha1::digest(&octets).to_vec(),
        Digest::Sha256 => Sha256::digest(&octets).to_vec(),
        Digest::Sha384 => Sha384::digest(&octets).to_vec(),
        Digest::Sha512 => Sha512::digest(&octets).to_vec(),
    };
    let expected = decode_base64(&reference.digest_value).ok_or(())?;
    Ok(computed == expected)
}

/// Enforce the e-dossier reference-scope rule.
///
/// This is the project's strongest defence against signature wrapping and the
/// one check a generic XMLDSig library cannot perform, because it depends on
/// what the container mandates rather than on what the signature claims.
fn reference_scope_check(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
    scope: SignatureScope,
    xades: Option<Node<'_, '_>>,
    references: &[Reference],
    resolved: &[Option<Node<'_, '_>>],
) -> Check {
    let namespace = context.namespace;
    // Each requirement lists the nodes that would satisfy it. An empty list
    // means the element the container mandates is not in the document at all,
    // which is itself a failure.
    let mut required: Vec<(&'static str, Vec<Node<'_, '_>>)> = Vec::new();
    match scope {
        SignatureScope::Document => {
            let Some(document) = signature.parent() else {
                return Check::unknown(
                    CheckCode::ReferenceScopeUnknown,
                    "the signature's containing document could not be determined",
                );
            };
            let profile = direct_child(document, namespace, "DocumentProfile");
            if profile.is_none() {
                // The core parser reports such a document as non-conformant and
                // skips it; without a profile the mandated set is undefined, so
                // the honest answer is that the scope is unknown.
                return Check::unknown(
                    CheckCode::ReferenceScopeUnknown,
                    "the containing document has no DocumentProfile, so the mandated reference set is undefined",
                );
            }
            required.push(("es:DocumentProfile", profile.into_iter().collect()));
            required.push((
                "es:Document/ds:Object",
                direct_children(document, XMLDSIG_NAMESPACE, "Object")
                    .find(|object| object.id() != signature.id())
                    .into_iter()
                    .collect(),
            ));
        }
        SignatureScope::Dossier => {
            required.push((
                "es:DossierProfile",
                direct_child(context.root_element(), namespace, "DossierProfile")
                    .into_iter()
                    .collect(),
            ));
            required.push((
                "es:Documents",
                direct_child(context.root_element(), namespace, "Documents")
                    .into_iter()
                    .collect(),
            ));
        }
        SignatureScope::Unknown => {
            return Check::unknown(
                CheckCode::ReferenceScopeUnknown,
                "the signature placement is not one the e-dossier format defines",
            );
        }
    }

    // The signature's own profile object. Real dossiers reference the
    // `es:SignatureProfile` element itself as often as the `ds:Object` that
    // wraps it, and the profile and qualifying-properties objects occur in
    // either order, so the object is found by content and both nodes satisfy
    // the requirement.
    required.push((
        "ds:Signature/ds:Object holding es:SignatureProfile",
        signature_profile_nodes(signature, context.allowed_namespaces),
    ));

    if xades.is_some() {
        // Decided by resolution: a reference that resolves to the
        // `SignedProperties` element, or to any ancestor of it (the
        // `QualifyingProperties` or the `ds:Object` around it), covers it.
        required.push((
            "xades:SignedProperties",
            signed_properties(signature).into_iter().collect(),
        ));
    }

    let covered: Vec<NodeId> = resolved.iter().flatten().map(|node| node.id()).collect();
    let is_covered = |node: Node<'_, '_>| {
        node.ancestors()
            .any(|candidate| covered.contains(&candidate.id()))
    };

    let mut missing: Vec<&'static str> = Vec::new();
    for (name, candidates) in required {
        if !candidates.iter().copied().any(is_covered) {
            missing.push(name);
        }
    }

    if missing.is_empty() {
        return Check::passed(
            CheckCode::ReferenceScopeComplete,
            "every element the e-dossier format requires this signature to cover is covered",
        );
    }
    // A `Type` attribute that announces a SignedProperties reference which does
    // not actually resolve to one is worth saying out loud: it is the shape a
    // wrapping attempt takes.
    let claimed = missing.contains(&"xades:SignedProperties")
        && references.iter().any(|reference| {
            reference
                .reference_type
                .as_deref()
                .is_some_and(|value| SIGNED_PROPERTIES_TYPES.contains(&value))
        });
    let note = if claimed {
        "; a reference declares the SignedProperties Type but does not resolve to one"
    } else {
        ""
    };
    Check::failed(
        CheckCode::ReferenceScopeIncomplete,
        format!("the signature does not cover: {}{note}", missing.join(", ")),
    )
}

/// The nodes that satisfy "the signature's own profile object": the direct
/// `ds:Object` child that contains an `es:SignatureProfile` in any allowed
/// dossier namespace, and that `es:SignatureProfile` element itself.
///
/// Located by content, never by position: the profile object and the
/// qualifying-properties object occur in either order in real dossiers.
fn signature_profile_nodes<'a, 'input>(
    signature: Node<'a, 'input>,
    allowed_namespaces: &[String],
) -> Vec<Node<'a, 'input>> {
    let mut nodes = Vec::new();
    for object in direct_children(signature, XMLDSIG_NAMESPACE, "Object") {
        let profile = object.descendants().find(|node| {
            node.is_element()
                && node.tag_name().name() == "SignatureProfile"
                && node.tag_name().namespace().is_some_and(|namespace| {
                    allowed_namespaces
                        .iter()
                        .any(|allowed| allowed == namespace)
                })
        });
        if let Some(profile) = profile {
            nodes.push(object);
            nodes.push(profile);
        }
    }
    if nodes.is_empty() {
        // A bare XMLDSig signature with no `es:SignatureProfile` still has to
        // cover its own object, if it has one.
        nodes.extend(direct_child(signature, XMLDSIG_NAMESPACE, "Object"));
    }
    nodes
}

/// The `xades:SignedProperties` element of this signature, in any XAdES
/// namespace this crate recognises.
fn signed_properties<'a, 'input>(signature: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    signature.descendants().find(|node| {
        node.is_element()
            && node.tag_name().name() == "SignedProperties"
            && node
                .tag_name()
                .namespace()
                .is_some_and(|namespace| XADES_NAMESPACES.contains(&namespace))
    })
}

impl<'a, 'input> Context<'a, 'input, '_> {
    fn root_element(&self) -> Node<'a, 'input> {
        self.root
            .children()
            .find(Node::is_element)
            .unwrap_or(self.root)
    }
}

fn parse_reference(node: Node<'_, '_>, index: usize) -> Reference {
    let transforms = direct_child(node, XMLDSIG_NAMESPACE, "Transforms")
        .map(|list| {
            direct_children(list, XMLDSIG_NAMESPACE, "Transform")
                .map(|transform| {
                    (
                        attribute(transform, "Algorithm")
                            .unwrap_or_default()
                            .to_owned(),
                        inclusive_prefixes(transform),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Reference {
        index,
        uri: attribute(node, "URI").unwrap_or_default().to_owned(),
        reference_type: attribute(node, "Type").map(str::to_owned),
        transforms,
        digest_uri: direct_child(node, XMLDSIG_NAMESPACE, "DigestMethod")
            .and_then(|method| attribute(method, "Algorithm"))
            .unwrap_or_default()
            .to_owned(),
        digest_value: direct_child(node, XMLDSIG_NAMESPACE, "DigestValue")
            .map(text_of)
            .unwrap_or_default(),
    }
}

/// The `PrefixList` of an `ec:InclusiveNamespaces` child, if present.
fn inclusive_prefixes(node: Node<'_, '_>) -> Vec<String> {
    direct_child(node, EXC_C14N_NAMESPACE, "InclusiveNamespaces")
        .and_then(|element| attribute(element, "PrefixList"))
        .map(|list| {
            list.split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn report_reference(
    reference: &Reference,
    node: Option<Node<'_, '_>>,
    status: CheckStatus,
) -> ReferenceReport {
    ReferenceReport {
        index: reference.index,
        uri: sanitize_uri(&reference.uri),
        resolved_to: node.map(element_path),
        digest_algorithm: Digest::from_digest_uri(&reference.digest_uri)
            .map(|digest| digest.as_str().to_owned()),
        transforms: reference
            .transforms
            .iter()
            .map(|(uri, _)| sanitize_uri(uri))
            .collect(),
        status,
    }
}

/// A reference URI comes from untrusted input, so it is bounded and stripped of
/// control characters before it is reported back.
fn sanitize_uri(uri: &str) -> String {
    uri.chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect()
}

/// A path of element names, so a caller can see *what* was signed without any
/// content leaving the tool.
fn element_path(node: Node<'_, '_>) -> String {
    let mut parts: Vec<String> = Vec::new();
    for element in std::iter::once(node)
        .chain(node.ancestors().skip(1))
        .filter(|candidate| candidate.is_element())
    {
        let name = element.tag_name().name();
        let plain = !name.is_empty()
            && name.len() <= 64
            && name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            });
        parts.push(if plain {
            name.to_owned()
        } else {
            "element".to_owned()
        });
    }
    parts.reverse();
    if parts.is_empty() {
        return "document".to_owned();
    }
    parts.join("/")
}

fn placement_of(context: &Context<'_, '_, '_>, signature: Node<'_, '_>) -> SignatureScope {
    let Some(parent) = signature.parent() else {
        return SignatureScope::Unknown;
    };
    if !parent.is_element() {
        return SignatureScope::Unknown;
    }
    if parent.tag_name().namespace() != Some(context.namespace) {
        return SignatureScope::Unknown;
    }
    match parent.tag_name().name() {
        "Document" => SignatureScope::Document,
        "Dossier" => SignatureScope::Dossier,
        _ => SignatureScope::Unknown,
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

fn is_known_c14n(uri: &str) -> bool {
    uri.starts_with("http://www.w3.org/TR/2001/REC-xml-c14n")
        || uri.starts_with("http://www.w3.org/2001/10/xml-exc-c14n")
        || uri.starts_with("http://www.w3.org/2006/12/xml-c14n11")
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64.decode(compact.as_bytes()).ok()
}

pub(crate) fn text_of(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect::<String>()
}

pub(crate) fn id_of<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    node.attribute("Id")
        .or_else(|| node.attribute("ID"))
        .or_else(|| node.attribute("id"))
}

pub(crate) fn attribute<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.attribute(name)
}

pub(crate) fn direct_children<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    let namespace = namespace.to_owned();
    node.children().filter(move |child| {
        child.is_element()
            && child.tag_name().namespace() == Some(namespace.as_str())
            && child.tag_name().name() == name
    })
}

pub(crate) fn direct_child<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &'static str,
) -> Option<Node<'a, 'input>> {
    direct_children(node, namespace, name).next()
}

/// The per-signature verdict, exposed so the caller can fold in stage D.
pub fn signature_verdict(checks: &[Check]) -> Verdict {
    verdict_of(checks)
}
