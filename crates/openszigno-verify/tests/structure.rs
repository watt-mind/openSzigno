//! XMLDSig cardinality and order, end to end over a signed synthetic dossier.
//!
//! The unit tests next to `signature/structure.rs` cover the sequence rules on
//! hand-built snippets. This suite proves the same rules hold on a dossier
//! that was really signed, so a duplicated or reordered critical child cannot
//! slip past stage A1 into a passed `signature_value_ok`.
//!
//! Every mutation here edits a signature that verified before the edit, and
//! each one must produce `sig_structure_invalid` with a verdict of `invalid`:
//! a structure failure is a failed check, and `verdict_of` maps any failed
//! check to `invalid` (see `docs/architecture.md`, stage A1).

mod common;

use common::{
    DossierSpec, assert_check, assert_no_failures, build, document_signature, has, run,
    run_without_trust, simple_pki,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{Verdict, VerifyReport};

const TIME: &str = "2020-06-01T00:00:00Z";

/// A dossier carrying one document-level signature, with nothing tampered.
fn signed_dossier() -> (String, Vec<u8>) {
    let pki = simple_pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    (xml, pki.root_der)
}

/// Insert `snippet` immediately after the first occurrence of `needle`.
fn insert_after(xml: &str, needle: &str, snippet: &str) -> String {
    let position = xml.find(needle).expect("the needle occurs") + needle.len();
    format!("{}{snippet}{}", &xml[..position], &xml[position..])
}

/// Insert `snippet` immediately before the first occurrence of `needle`.
fn insert_before(xml: &str, needle: &str, snippet: &str) -> String {
    let position = xml.find(needle).expect("the needle occurs");
    format!("{}{snippet}{}", &xml[..position], &xml[position..])
}

/// The first `open .. close` span, inclusive of both ends.
fn span(xml: &str, open: &str, close: &str) -> String {
    let start = xml.find(open).expect("the opening tag occurs");
    let end = xml[start..].find(close).expect("the closing tag occurs") + start + close.len();
    xml[start..end].to_owned()
}

/// Duplicate the first `open .. close` span in place.
fn duplicate(xml: &str, open: &str, close: &str) -> String {
    let copy = span(xml, open, close);
    insert_after(xml, &copy, &copy)
}

/// Every self-closing element is rendered as one `<name ... />` run, so its
/// span ends at the first `>` after the name.
fn duplicate_empty(xml: &str, open: &str) -> String {
    duplicate(xml, open, ">")
}

fn assert_structure_invalid(report: &VerifyReport) {
    assert_check(report, CheckCode::SigStructureInvalid, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
    assert!(
        !has(report, CheckCode::SignatureValueOk, CheckStatus::Passed),
        "a signature that failed stage A1 must never reach signature_value_ok"
    );
    assert!(
        !has(report, CheckCode::SigStructure, CheckStatus::Passed),
        "the passing structure check must not be emitted alongside the failure"
    );
}

/// Mutate the signed dossier, verify it, and assert the structural refusal.
fn assert_mutation_is_refused(mutate: impl Fn(&str) -> String) {
    let (xml, root) = signed_dossier();
    let report = run(&xml, vec![root.clone()], TIME);
    assert_no_failures(&report);

    let mutated = mutate(&xml);
    assert_ne!(mutated, xml, "the mutation changed the dossier");
    let report = run(&mutated, vec![root], TIME);
    assert_structure_invalid(&report);
}

// ---------------------------------------------------------------------------
// Duplicated critical children
// ---------------------------------------------------------------------------

#[test]
fn a_second_signed_info_is_refused() {
    assert_mutation_is_refused(|xml| duplicate(xml, "<ds:SignedInfo>", "</ds:SignedInfo>"));
}

#[test]
fn a_second_signature_value_is_refused() {
    assert_mutation_is_refused(|xml| {
        insert_after(
            xml,
            "</ds:SignatureValue>",
            "<ds:SignatureValue>AA==</ds:SignatureValue>",
        )
    });
}

#[test]
fn a_second_canonicalization_method_is_refused() {
    assert_mutation_is_refused(|xml| duplicate_empty(xml, "<ds:CanonicalizationMethod"));
}

#[test]
fn a_second_signature_method_is_refused() {
    assert_mutation_is_refused(|xml| duplicate_empty(xml, "<ds:SignatureMethod"));
}

#[test]
fn a_second_transforms_is_refused() {
    assert_mutation_is_refused(|xml| duplicate(xml, "<ds:Transforms>", "</ds:Transforms>"));
}

#[test]
fn a_second_digest_method_is_refused() {
    assert_mutation_is_refused(|xml| duplicate_empty(xml, "<ds:DigestMethod"));
}

#[test]
fn a_second_digest_value_is_refused() {
    assert_mutation_is_refused(|xml| {
        insert_after(
            xml,
            "</ds:DigestValue>",
            "<ds:DigestValue>AA==</ds:DigestValue>",
        )
    });
}

#[test]
fn a_second_key_info_is_refused() {
    assert_mutation_is_refused(|xml| duplicate(xml, "<ds:KeyInfo>", "</ds:KeyInfo>"));
}

// ---------------------------------------------------------------------------
// Out-of-order children
// ---------------------------------------------------------------------------

#[test]
fn a_signature_value_before_signed_info_is_refused() {
    assert_mutation_is_refused(|xml| {
        let value = span(xml, "<ds:SignatureValue", "</ds:SignatureValue>");
        let moved = xml.replacen(&value, "", 1);
        insert_before(&moved, "<ds:SignedInfo>", &value)
    });
}

#[test]
fn a_digest_value_before_its_digest_method_is_refused() {
    assert_mutation_is_refused(|xml| {
        let method = span(xml, "<ds:DigestMethod", ">");
        let value = span(xml, "<ds:DigestValue", "</ds:DigestValue>");
        let pair = format!("{method}{value}");
        xml.replacen(&pair, &format!("{value}{method}"), 1)
    });
}

#[test]
fn key_info_after_an_object_is_refused() {
    assert_mutation_is_refused(|xml| {
        let key_info = span(xml, "<ds:KeyInfo>", "</ds:KeyInfo>");
        let moved = xml.replacen(&key_info, "", 1);
        insert_before(&moved, "</ds:Signature>", &key_info)
    });
}

// ---------------------------------------------------------------------------
// Foreign namespaces at the sequenced elements
// ---------------------------------------------------------------------------

#[test]
fn a_foreign_child_of_signed_info_is_refused() {
    assert_mutation_is_refused(|xml| {
        insert_before(
            xml,
            "</ds:SignedInfo>",
            "<x:Extra xmlns:x=\"urn:example:intruder\"/>",
        )
    });
}

#[test]
fn a_foreign_child_of_the_signature_is_refused() {
    assert_mutation_is_refused(|xml| {
        insert_before(
            xml,
            "</ds:Signature>",
            "<x:Extra xmlns:x=\"urn:example:intruder\"/>",
        )
    });
}

#[test]
fn a_foreign_child_of_a_reference_is_refused() {
    assert_mutation_is_refused(|xml| {
        insert_before(
            xml,
            "</ds:Reference>",
            "<x:Extra xmlns:x=\"urn:example:intruder\"/>",
        )
    });
}

// ---------------------------------------------------------------------------
// The extension points stay open
// ---------------------------------------------------------------------------

/// `ds:KeyInfo`, several `ds:Object` elements, and comments between the
/// children are all what the schema allows, so the signature still verifies.
#[test]
fn key_info_extra_objects_and_comments_still_verify() {
    let (xml, root) = signed_dossier();
    let mutated = insert_before(
        &insert_after(
            &insert_after(&xml, "</ds:SignedInfo>", "<!-- between the two halves -->"),
            "</ds:SignatureValue>",
            "<!-- before the key -->",
        ),
        "</ds:Signature>",
        "<ds:Object Id=\"extra-object-1\"><x:Anything xmlns:x=\"urn:example:extension\"/>\
</ds:Object><!-- between the objects --><ds:Object Id=\"extra-object-2\"/>",
    );
    assert!(mutated.contains("extra-object-2"));

    let report = run(&mutated, vec![root], TIME);
    assert_no_failures(&report);
    assert_check(&report, CheckCode::SigStructure, CheckStatus::Passed);
    assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
}

/// The structural pass runs before trust material is consulted, so it refuses
/// the same shapes with no anchors configured.
#[test]
fn the_structural_refusal_does_not_depend_on_trust() {
    let (xml, _) = signed_dossier();
    let mutated = insert_after(
        &xml,
        "</ds:SignatureValue>",
        "<ds:SignatureValue>AA==</ds:SignatureValue>",
    );
    let report = run_without_trust(&mutated, TIME);
    assert_structure_invalid(&report);
}
