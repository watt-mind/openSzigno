//! Placement, reference scope, and the signature shapes the private corpus
//! showed.
//!
//! These are the checks that depend on the *container's* rules rather than on
//! cryptography: where a `ds:Signature` may sit, which elements the e-dossier
//! format then mandates it cover, and what a reference's transforms leave in
//! the effective node set. The rest of the end-to-end suite is in `verify.rs`;
//! both drive the same harness from [`common::harness`].

mod common;

use common::{
    C14N_EXC, CounterSignatureSpec, DossierSpec, RefSpec, SIGNED_PROPERTIES_TYPE, XSLT_URI,
    assert_check, assert_no_failures, build, countersignature, document_signature,
    dossier_signature, run, run_without_trust, simple_pki,
};
use openszigno_verify::Verdict;
use openszigno_verify::codes::{CheckCode, CheckStatus};

// ---------------------------------------------------------------------------
// Placement and scope edge cases
// ---------------------------------------------------------------------------

/// A signature somewhere the e-dossier format does not describe fails
/// placement; the scope of such a signature is unknown rather than complete.
#[test]
fn a_signature_in_an_undefined_place_fails_placement() {
    let xml = misplaced_signature();
    let report = run_without_trust(&xml, "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::SigPlacementInvalid, CheckStatus::Failed);
    assert_check(
        &report,
        CheckCode::ReferenceScopeUnknown,
        CheckStatus::Unknown,
    );
}

/// A `Document` without a `DocumentProfile` is non-conformant; the mandated
/// reference set is then undefined, so the honest answer is `unknown`.
#[test]
fn a_document_without_a_profile_makes_the_scope_unknown() {
    let xml = signature_on_a_profileless_document();
    let report = run_without_trust(&xml, "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::ReferenceScopeUnknown,
        CheckStatus::Unknown,
    );
}

/// A signature with no `ds:SignedInfo` cannot be examined at all.
#[test]
fn a_malformed_signature_fails_structure() {
    let xml = structurally_broken_signature();
    let report = run_without_trust(&xml, "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::SigStructureInvalid, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
}

fn misplaced_signature() -> String {
    wrap(
        r#"<es:DossierProfile Id="dossier-profile" OBJREF="documents"><es:Title>t</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate></es:DossierProfile><es:Documents Id="documents"><es:Document><es:DocumentProfile Id="prof0" OBJREF="obj0"><es:Title>a</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="text" subtype="plain"/></es:Format><es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform></es:DocumentProfile><ds:Object Id="obj0">aGVsbG8=</ds:Object><es:Wrapper><ds:Signature Id="sig-odd">"#.to_owned()
            + &signed_info("#obj0")
            + r#"<ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature></es:Wrapper></es:Document></es:Documents>"#,
    )
}

fn signature_on_a_profileless_document() -> String {
    wrap(
        r#"<es:DossierProfile Id="dossier-profile" OBJREF="documents"><es:Title>t</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate></es:DossierProfile><es:Documents Id="documents"><es:Document><ds:Object Id="obj0">aGVsbG8=</ds:Object><ds:Signature Id="sig-orphan">"#.to_owned()
            + &signed_info("#obj0")
            + r#"<ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature></es:Document></es:Documents>"#,
    )
}

fn structurally_broken_signature() -> String {
    wrap(
        r#"<es:DossierProfile Id="dossier-profile" OBJREF="documents"><es:Title>t</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate></es:DossierProfile><es:Documents Id="documents"><es:Document><es:DocumentProfile Id="prof0" OBJREF="obj0"><es:Title>a</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="text" subtype="plain"/></es:Format><es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform></es:DocumentProfile><ds:Object Id="obj0">aGVsbG8=</ds:Object><ds:Signature Id="sig-broken"></ds:Signature></es:Document></es:Documents>"#.to_owned(),
    )
}

fn signed_info(uri: &str) -> String {
    format!(
        r#"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{C14N_EXC}"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="{uri}"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference></ds:SignedInfo>"#
    )
}

fn wrap(body: String) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<es:Dossier xmlns:es=\"{}\" xmlns:ds=\"{}\">{body}</es:Dossier>",
        common::ESZIGNO_NS,
        common::DS_NS
    )
}

// ---------------------------------------------------------------------------
// Shapes the private corpus showed
// ---------------------------------------------------------------------------
//
// Real dossiers reference the `es:SignatureProfile` element rather than the
// `ds:Object` around it, place the profile and qualifying-properties objects in
// either order, and use XAdES 1.2.2 with a versioned `SignedProperties` Type.
// Each of those made every corpus signature stop at
// `reference_scope_incomplete` before any digest was recomputed.

/// A reference to the `es:SignatureProfile` element itself satisfies the
/// "own profile object" requirement, exactly as one to the `ds:Object` does.
#[test]
fn referencing_the_signature_profile_element_covers_the_profile_object() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[2] = RefSpec::to("#sigprof-doc");
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_no_failures(&report);
    assert_check(
        &report,
        CheckCode::ReferenceScopeComplete,
        CheckStatus::Passed,
    );
    assert_eq!(
        report.signatures[0].references[2].resolved_to.as_deref(),
        Some("Dossier/Documents/Document/Signature/Object/SignatureProfile")
    );
}

/// The profile object is found by content, so the order of the signature's
/// `ds:Object` children does not matter.
#[test]
fn the_profile_object_is_found_whichever_order_the_objects_are_in() {
    for reversed in [false, true] {
        let pki = simple_pki();
        let mut signature = dossier_signature(pki.chain.clone());
        signature.objects_reversed = reversed;
        let spec = DossierSpec {
            dossier_signature: Some(signature),
            ..Default::default()
        };
        let xml = build(&spec, &[("frame", &pki.signer_key)]);
        let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
        assert_no_failures(&report);
        assert_check(
            &report,
            CheckCode::ReferenceScopeComplete,
            CheckStatus::Passed,
        );
    }
}

/// Legacy XAdES 1.2.2, with the versioned `SignedProperties` Type URI, is
/// detected and its properties count as covered.
#[test]
fn legacy_xades_122_is_detected_and_its_signed_properties_are_covered() {
    let pki = simple_pki();
    let mut signature = dossier_signature(pki.chain.clone());
    signature.xades_namespace = common::XADES_NS_122.to_owned();
    signature.references[3] = RefSpec {
        reference_type: Some(common::SIGNED_PROPERTIES_TYPE_122.to_owned()),
        ..RefSpec::to("#sp-frame")
    };
    let spec = DossierSpec {
        dossier_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("frame", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_no_failures(&report);
    assert_check(&report, CheckCode::XadesPresent, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::ReferenceScopeComplete,
        CheckStatus::Passed,
    );
    assert_eq!(report.signatures[0].xades_level, Some("detected"));
}

/// Coverage is decided by resolution, not by the `Type` attribute: a reference
/// that declares the SignedProperties type but resolves elsewhere does not
/// satisfy the requirement, and the message says so.
#[test]
fn a_signed_properties_type_cannot_stand_in_for_resolution() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[3] = RefSpec {
        reference_type: Some(SIGNED_PROPERTIES_TYPE.to_owned()),
        ..RefSpec::to("#prof0")
    };
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::ReferenceScopeIncomplete,
        CheckStatus::Failed,
    );
    let message = report.signatures[0]
        .checks
        .iter()
        .find(|check| check.code == CheckCode::ReferenceScopeIncomplete)
        .map(|check| check.message.clone())
        .expect("the check was emitted");
    assert!(
        message.contains("declares the SignedProperties Type"),
        "{message}"
    );
}

/// A reference to the `ds:Object` that wraps the qualifying properties covers
/// the `SignedProperties` inside it: the ancestor is still in the effective
/// node set, because no transform removed it.
#[test]
fn a_reference_to_an_ancestor_covers_the_signed_properties() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    // The qualifying-properties `ds:Object`, not the `SignedProperties` the
    // other three references name directly.
    signature.references[3] = RefSpec::to("#xadesobj-doc").with_transforms(&[C14N_EXC]);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_no_failures(&report);
    assert_check(&report, CheckCode::XadesPresent, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::ReferenceScopeComplete,
        CheckStatus::Passed,
    );
    assert_eq!(
        report.signatures[0].references[3].resolved_to.as_deref(),
        Some("Dossier/Documents/Document/Signature/Object")
    );
}

/// Covering a *different* signature's own profile object does not satisfy
/// this signature's "own profile object" requirement: the candidate nodes
/// `signature_profile_nodes` returns for one signature are guarded to belong
/// to that signature (`owning_signature(*node) == Some(signature)`), so a
/// reference from the outer signature that points at its nested
/// countersignature's profile object instead of its own leaves the outer
/// signature's own requirement uncovered.
#[test]
fn covering_a_nested_signatures_profile_object_does_not_cover_this_signatures_own() {
    let pki = simple_pki();
    let mut outer = document_signature(pki.chain.clone());
    outer.signature_value_id = Some("sigval-doc".to_owned());
    // Point the "own profile object" reference at the countersignature's
    // profile object instead of the outer signature's own `#sigobj-doc`.
    outer.references[2] = RefSpec::to("#sigobj-csig");
    outer.countersignatures = vec![CounterSignatureSpec::new(countersignature(
        "csig",
        pki.chain.clone(),
        "sigval-doc",
    ))];
    let spec = DossierSpec {
        document_signature: Some(outer),
        ..Default::default()
    };
    let xml = build(
        &spec,
        &[("doc", &pki.signer_key), ("csig", &pki.signer_key)],
    );
    let report = run_without_trust(&xml, "2020-06-01T00:00:00Z");

    assert_check(
        &report,
        CheckCode::ReferenceScopeIncomplete,
        CheckStatus::Failed,
    );
    let message = report.signatures[0]
        .checks
        .iter()
        .find(|check| check.code == CheckCode::ReferenceScopeIncomplete)
        .map(|check| check.message.clone())
        .expect("the check was emitted");
    assert!(
        message.contains("ds:Signature/ds:Object holding es:SignatureProfile"),
        "{message}"
    );
}

/// A caller must always see what each URI resolved to, even when the run
/// stopped before any digest was recomputed.
#[test]
fn resolved_to_is_reported_even_when_the_policy_stage_fails() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[0] = RefSpec::to("#obj0").with_transforms(&[XSLT_URI, C14N_EXC]);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::TransformNotAllowed, CheckStatus::Failed);
    let references = &report.signatures[0].references;
    assert_eq!(references.len(), 4);
    for reference in references {
        assert_eq!(reference.status, CheckStatus::Skipped);
        assert!(
            reference.resolved_to.is_some(),
            "{} resolved to nothing",
            reference.uri
        );
    }
    assert_eq!(
        references[0].resolved_to.as_deref(),
        Some("Dossier/Documents/Document/Object")
    );
}
