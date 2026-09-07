//! The bounded, unverified signature inventory.
//!
//! Every dossier here is synthesised by this file. The signature values,
//! certificates, and timestamp tokens are the placeholder `AA==`: the
//! inventory describes what the XML claims and never decodes any of it, so
//! nothing in these tests needs to be real, and nothing they assert is a
//! statement about validity.

mod common;

use common::PLAIN;
use openszigno_core::{
    Limits, MAX_INVENTORIED_SIGNATURES, SignaturePlacement, TimestampPlacement, parse,
};

const XADES_132: &str = "http://uri.etsi.org/01903/v1.3.2#";

/// A dossier with one document, plus caller-chosen extra elements inside the
/// document and directly under the root.
fn dossier(document_extras: &str, dossier_extras: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
<es:DossierProfile Id="DossierProfile1" OBJREF="Object0"><es:Title>Synthetic inventory fixture</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate></es:DossierProfile>
<es:Documents Id="Object0">
<es:Document>
<es:DocumentProfile Id="DocumentProfile0" OBJREF="DocumentObject0"><es:Title>hello.txt</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format><es:SourceSize sizeValue="5" sizeUnit="B"/><es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform></es:DocumentProfile>
<ds:Object Id="DocumentObject0">aGVsbG8=</ds:Object>
{document_extras}
</es:Document>
</es:Documents>
{dossier_extras}
</es:Dossier>"#
    )
}

/// A `ds:SignedInfo` with the given references, each carrying a digest method.
fn signed_info(references: &[(&str, &str)]) -> String {
    let references: String = references
        .iter()
        .map(|(uri, digest)| {
            format!(
                concat!(
                    r#"<ds:Reference URI="{uri}"><ds:DigestMethod Algorithm="{digest}"/>"#,
                    "<ds:DigestValue>AA==</ds:DigestValue></ds:Reference>"
                ),
                uri = uri,
                digest = digest,
            )
        })
        .collect();
    format!(
        concat!(
            "<ds:SignedInfo>",
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>"#,
            r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>"#,
            "{references}</ds:SignedInfo>",
        ),
        references = references,
    )
}

const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

/// A document-level signature carrying XAdES properties, every kind of
/// evidence container, and a countersignature.
fn document_signature() -> String {
    format!(
        concat!(
            r#"<ds:Signature Id="doc-sig">"#,
            "{signed_info}",
            "<ds:SignatureValue>AA==</ds:SignatureValue>",
            "<ds:KeyInfo><ds:X509Data>",
            "<ds:X509Certificate>AA==</ds:X509Certificate>",
            "<ds:X509Certificate>AA==</ds:X509Certificate>",
            "</ds:X509Data></ds:KeyInfo>",
            r##"<ds:Object><xades:QualifyingProperties Target="#doc-sig">"##,
            r#"<xades:SignedProperties Id="doc-sig-properties"><xades:SignedSignatureProperties>"#,
            "<xades:SigningTime>2026-01-02T03:04:05Z</xades:SigningTime>",
            "<xades:SigningCertificateV2><xades:Cert/></xades:SigningCertificateV2>",
            "<xades:SignaturePolicyIdentifier/>",
            "</xades:SignedSignatureProperties></xades:SignedProperties>",
            "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>",
            "<xades:SignatureTimeStamp>",
            "<xades:EncapsulatedTimeStamp>AA==</xades:EncapsulatedTimeStamp>",
            "</xades:SignatureTimeStamp>",
            "<xades:CertificateValues>",
            "<xades:EncapsulatedX509Certificate>AA==</xades:EncapsulatedX509Certificate>",
            "</xades:CertificateValues>",
            "<xades:RevocationValues>",
            "<xades:CRLValues><xades:EncapsulatedCRLValue>AA==</xades:EncapsulatedCRLValue></xades:CRLValues>",
            "<xades:OCSPValues><xades:EncapsulatedOCSPValue>AA==</xades:EncapsulatedOCSPValue></xades:OCSPValues>",
            "</xades:RevocationValues>",
            "<xades:ArchiveTimeStamp>",
            "<xades:EncapsulatedTimeStamp>AA==</xades:EncapsulatedTimeStamp>",
            "</xades:ArchiveTimeStamp>",
            "<xades:CounterSignature>{counter}</xades:CounterSignature>",
            "</xades:UnsignedSignatureProperties></xades:UnsignedProperties>",
            "</xades:QualifyingProperties></ds:Object></ds:Signature>",
        ),
        signed_info = signed_info(&[
            ("#DocumentProfile0", SHA256),
            ("#DocumentObject0", SHA256),
            ("https://example.invalid/external", SHA512),
        ]),
        counter = counter_signature(),
    )
}

/// A countersignature, with evidence of its own so that the signature it sits
/// inside must not report it.
fn counter_signature() -> String {
    format!(
        concat!(
            r#"<ds:Signature Id="counter-sig">"#,
            "{signed_info}",
            "<ds:SignatureValue>AA==</ds:SignatureValue>",
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>AA==</ds:X509Certificate>",
            "</ds:X509Data></ds:KeyInfo>",
            r##"<ds:Object><xades:QualifyingProperties Target="#counter-sig">"##,
            r#"<xades:SignedProperties Id="counter-sig-properties"><xades:SignedSignatureProperties>"#,
            "<xades:SigningTime>2026-02-03T04:05:06Z</xades:SigningTime>",
            "</xades:SignedSignatureProperties></xades:SignedProperties>",
            "</xades:QualifyingProperties></ds:Object></ds:Signature>",
        ),
        signed_info = signed_info(&[("#doc-sig-value", SHA256)]),
    )
}

fn dossier_signature(id: &str) -> String {
    format!(
        r#"<ds:Signature Id="{id}">{signed_info}<ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"#,
        id = id,
        signed_info = signed_info(&[("#Object0", SHA256)]),
    )
}

fn timestamp(includes: &[&str], token: Option<&str>) -> String {
    let includes: String = includes
        .iter()
        .map(|uri| format!(r#"<xades:Include URI="{uri}"/>"#))
        .collect();
    let token = token.map_or_else(String::new, |value| {
        format!("<xades:EncapsulatedTimeStamp>{value}</xades:EncapsulatedTimeStamp>")
    });
    format!("<es:TimeStamp>{includes}{token}</es:TimeStamp>")
}

#[test]
fn a_document_signature_is_described_field_by_field() {
    let xml = dossier(&document_signature(), "");
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");

    assert_eq!(dossier.signatures_present, 2, "the countersignature counts");
    assert_eq!(dossier.signatures.len(), 2);
    let signature = &dossier.signatures[0];
    assert_eq!(signature.id.as_deref(), Some("doc-sig"));
    assert_eq!(signature.placement, SignaturePlacement::Document);
    assert_eq!(signature.document_index, Some(0));
    assert_eq!(signature.parent_signature_id, None);
    assert_eq!(
        signature.canonicalization_method.as_deref(),
        Some("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
    );
    assert_eq!(
        signature.signature_method.as_deref(),
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    );
    assert_eq!(signature.digest_methods, vec![SHA256, SHA512]);
    assert_eq!(signature.reference_count, 3);
    assert_eq!(signature.xades_namespace.as_deref(), Some(XADES_132));
    assert_eq!(
        signature.xades_properties,
        vec![
            "SigningTime",
            "SigningCertificateV2",
            "SignaturePolicyIdentifier",
            "SignatureTimeStamp",
            "CertificateValues",
            "RevocationValues",
            "ArchiveTimeStamp",
            "CounterSignature",
        ]
    );
    assert_eq!(signature.evidence.certificates, 1);
    assert_eq!(signature.evidence.crls, 1);
    assert_eq!(signature.evidence.ocsp_responses, 1);
    assert_eq!(signature.evidence.signature_timestamps, 1);
    assert_eq!(signature.evidence.archive_timestamps, 1);
    assert_eq!(
        signature.claimed_signing_time.as_deref(),
        Some("2026-01-02T03:04:05Z")
    );
    assert_eq!(
        signature.key_info_certificates, 2,
        "the countersignature's own certificate must not be counted here"
    );
}

#[test]
fn a_countersignature_is_inventoried_in_its_own_right() {
    let xml = dossier(&document_signature(), "");
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");

    let counter = &dossier.signatures[1];
    assert_eq!(counter.id.as_deref(), Some("counter-sig"));
    assert_eq!(counter.placement, SignaturePlacement::NestedInSignature);
    assert_eq!(counter.parent_signature_id.as_deref(), Some("doc-sig"));
    assert_eq!(counter.document_index, None);
    assert_eq!(counter.key_info_certificates, 1);
    assert_eq!(counter.reference_uris, vec!["#doc-sig-value"]);
    assert_eq!(
        counter.claimed_signing_time.as_deref(),
        Some("2026-02-03T04:05:06Z")
    );
    assert_eq!(counter.xades_properties, vec!["SigningTime"]);
    assert_eq!(counter.evidence.certificates, 0);
}

#[test]
fn a_dossier_level_signature_reports_dossier_placement() {
    let xml = dossier("", &dossier_signature("dossier-sig"));
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");

    assert_eq!(dossier.signatures.len(), 1);
    let signature = &dossier.signatures[0];
    assert_eq!(signature.placement, SignaturePlacement::Dossier);
    assert_eq!(signature.id.as_deref(), Some("dossier-sig"));
    assert_eq!(signature.document_index, None);
    assert_eq!(signature.xades_namespace, None);
    assert!(signature.xades_properties.is_empty());
    assert_eq!(signature.claimed_signing_time, None);
    assert_eq!(signature.key_info_certificates, 0);
}

#[test]
fn reference_uris_are_reported_without_being_resolved() {
    let signature = format!(
        r#"<ds:Signature Id="dangling-sig">{}<ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"#,
        signed_info(&[
            ("#no-such-element", SHA256),
            ("", SHA256),
            ("https://example.invalid/off-document", SHA256),
        ]),
    );
    let xml = dossier("", &signature);
    let dossier =
        parse(xml.as_bytes(), &Limits::default()).expect("an unresolved URI still parses");

    let signature = &dossier.signatures[0];
    assert_eq!(signature.reference_count, 3);
    assert_eq!(
        signature.reference_uris,
        vec!["#no-such-element", ""],
        "same-document URIs are listed verbatim and an off-document one is left out"
    );
    assert!(
        dossier.warnings.is_empty(),
        "an unresolved ds:Reference URI is not a structural finding"
    );
}

#[test]
fn container_timestamps_are_described_by_placement() {
    let xml = dossier(
        &timestamp(&["#DocumentObject0"], None),
        &timestamp(&["#DossierProfile1", "#Object0"], Some("AA==")),
    );
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");

    assert_eq!(dossier.timestamps_present, 2);
    assert_eq!(dossier.timestamps.len(), 2);
    let document = &dossier.timestamps[0];
    assert_eq!(document.placement, TimestampPlacement::Document);
    assert_eq!(document.document_index, Some(0));
    assert_eq!(document.include_count, 1);
    assert!(!document.has_token);
    let container = &dossier.timestamps[1];
    assert_eq!(container.placement, TimestampPlacement::Dossier);
    assert_eq!(container.document_index, None);
    assert_eq!(container.include_count, 2);
    assert!(container.has_token);
}

#[test]
fn an_unsigned_dossier_has_an_empty_inventory() {
    let dossier = parse(PLAIN.as_bytes(), &Limits::default()).expect("the fixture parses");

    assert_eq!(dossier.signatures_present, 0);
    assert!(dossier.signatures.is_empty());
    assert!(dossier.timestamps.is_empty());
}

#[test]
fn the_inventory_stops_at_the_limit_and_says_so() {
    let signatures: String = (0..=MAX_INVENTORIED_SIGNATURES)
        .map(|index| dossier_signature(&format!("sig-{index}")))
        .collect();
    let xml = dossier("", &signatures);
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");

    assert_eq!(dossier.signatures_present, MAX_INVENTORIED_SIGNATURES + 1);
    assert_eq!(dossier.signatures.len(), MAX_INVENTORIED_SIGNATURES);
    assert_eq!(
        dossier.signatures.last().expect("there are signatures").id,
        Some(format!("sig-{}", MAX_INVENTORIED_SIGNATURES - 1))
    );
    let codes: Vec<_> = dossier
        .warnings
        .iter()
        .map(|warning| warning.code.as_str())
        .collect();
    assert_eq!(codes, vec!["signature_inventory_truncated"]);
}

#[test]
fn hostile_values_are_left_out_rather_than_echoed() {
    let signature = format!(
        concat!(
            "<ds:Signature Id=\"a b\">{signed_info}",
            r##"<ds:Object><xades:QualifyingProperties Target="#x">"##,
            "<xades:SignedProperties><xades:SignedSignatureProperties>",
            "<xades:SigningTime>2026-01-01T00:00:00Z\nTitle: secret</xades:SigningTime>",
            "</xades:SignedSignatureProperties></xades:SignedProperties>",
            "</xades:QualifyingProperties></ds:Object></ds:Signature>",
        ),
        signed_info = signed_info(&[("#Object0", "a\nb")]),
    );
    let xml = dossier("", &signature);
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");

    let signature = &dossier.signatures[0];
    assert_eq!(signature.id, None, "an Id that is not a name is not echoed");
    assert!(
        signature.digest_methods.is_empty(),
        "an algorithm URI with a newline in it is not echoed"
    );
    assert_eq!(
        signature.claimed_signing_time, None,
        "a signing time that is not a plain token is not echoed"
    );
    assert_eq!(signature.reference_count, 1);
}

#[test]
fn the_inventory_serialises_with_the_documented_names() {
    let xml = dossier(
        &document_signature(),
        &timestamp(&["#Object0"], Some("AA==")),
    );
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");
    let value = serde_json::to_value(&dossier).expect("the dossier serialises");

    let signature = &value["signatures"][0];
    assert_eq!(signature["placement"], "document");
    assert_eq!(signature["document_index"], 0);
    assert_eq!(signature["evidence"]["ocsp_responses"], 1);
    assert_eq!(signature["key_info_certificates"], 2);
    assert_eq!(value["signatures"][1]["placement"], "nested_in_signature");
    assert_eq!(value["timestamps"][0]["placement"], "dossier");
    assert_eq!(value["timestamps"][0]["has_token"], true);
}

#[test]
fn placements_have_stable_strings() {
    assert_eq!(SignaturePlacement::Document.as_str(), "document");
    assert_eq!(SignaturePlacement::Dossier.as_str(), "dossier");
    assert_eq!(
        SignaturePlacement::NestedInSignature.as_str(),
        "nested_in_signature"
    );
    assert_eq!(SignaturePlacement::Other.as_str(), "other");
    assert_eq!(TimestampPlacement::Dossier.as_str(), "dossier");
    assert_eq!(TimestampPlacement::Document.as_str(), "document");
    assert_eq!(TimestampPlacement::Other.as_str(), "other");
}

#[test]
fn a_signature_the_format_does_not_place_is_reported_as_other() {
    let xml = dossier("", "").replace(
        "</es:Documents>",
        &format!("{}</es:Documents>", dossier_signature("stray-sig")),
    );
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");

    let signature = &dossier.signatures[0];
    assert_eq!(signature.placement, SignaturePlacement::Other);
    assert_eq!(signature.document_index, None);
    assert_eq!(signature.parent_signature_id, None);
}

#[test]
fn a_timestamp_the_format_does_not_place_is_reported_as_other() {
    let xml = dossier("", "").replace(
        "</es:Documents>",
        &format!("{}</es:Documents>", timestamp(&["#Object0"], None)),
    );
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");

    assert_eq!(dossier.timestamps[0].placement, TimestampPlacement::Other);
    assert_eq!(dossier.timestamps[0].document_index, None);
}
