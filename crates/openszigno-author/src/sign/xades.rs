//! The XAdES half of a signature: `xades:QualifyingProperties` and what goes
//! in it.
//!
//! The signed half is the part that matters. `xades:SignedProperties` carries
//! the `SigningTime` and the `SigningCertificateV2` binding, it is referenced
//! by a `ds:Reference` of its own, and the e-dossier reference-scope rule this
//! project enforces requires exactly that: a signature that relies on a
//! whole-document reference covers nothing inside itself, so the binding would
//! not be signed at all.
//!
//! The unsigned half carries evidence and nothing else: the certificates a
//! verifier needs to build a path without a store, and the RFC 3161 token that
//! says when the signature existed. Nothing there can change what the
//! signature says, which is why it can be filled in after the signature value.

use super::dsig::{PlannedReference, SHA256_URI, base64};
use super::signer::certificate_digest;

/// XAdES 1.3.2, the namespace this build writes.
///
/// It is the one the verifier treats as standard and the one the corpus is
/// written in; 1.1.1, 1.2.2 and 1.4.1 are recognised when reading and are
/// never produced.
pub(crate) const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";

/// The placeholder a timestamp token is written under until the TSA has
/// answered.
pub(crate) fn timestamp_placeholder(signature_id: &str) -> String {
    format!("@@openszigno-timestamp:{signature_id}@@")
}

/// What the qualifying properties of one signature should carry.
pub(crate) struct QualifyingPlan<'a> {
    pub(crate) signature_id: &'a str,
    pub(crate) signed_properties_id: &'a str,
    /// RFC 3339 UTC seconds, as the caller formatted it. This crate reads no
    /// clock.
    pub(crate) signing_time: &'a str,
    /// The signing certificate, DER, which the signed property digests.
    pub(crate) certificate: &'a [u8],
    /// The references, so each data object gets an `xades:DataObjectFormat`.
    pub(crate) references: &'a [PlannedReference],
    /// Certificates to place in `xades:CertificateValues`, so a verifier can
    /// build the signer's and the timestamp authority's paths without being
    /// handed the intermediates separately.
    pub(crate) certificate_values: &'a [Vec<u8>],
    /// Whether to write an `xades:SignatureTimeStamp` placeholder.
    pub(crate) timestamped: bool,
}

/// Render the `ds:Object` holding this signature's qualifying properties.
pub(crate) fn render_qualifying_properties(plan: &QualifyingPlan<'_>) -> String {
    let mut signed = String::new();
    signed.push_str("<xades:SignedSignatureProperties>");
    signed.push_str(&format!(
        "<xades:SigningTime>{}</xades:SigningTime>",
        plan.signing_time
    ));
    // `SigningCertificateV2` with the digest alone. `IssuerSerialV2` is
    // optional in EN 319 132-1 and is deliberately not written: the digest is
    // the binding, the issuer and serial are corroboration, and corroboration
    // that could disagree with the digest is a failure mode with no upside
    // here, where both would be written from the same certificate.
    signed.push_str(&format!(
        "<xades:SigningCertificateV2><xades:Cert><xades:CertDigest>\
<ds:DigestMethod Algorithm=\"{SHA256_URI}\"/>\
<ds:DigestValue>{}</ds:DigestValue>\
</xades:CertDigest></xades:Cert></xades:SigningCertificateV2>",
        base64(&certificate_digest(plan.certificate))
    ));
    signed.push_str("</xades:SignedSignatureProperties>");

    let formats: String = plan
        .references
        .iter()
        .filter_map(|reference| {
            let mime_type = reference.mime_type.as_ref()?;
            Some(format!(
                "<xades:DataObjectFormat ObjectReference=\"#{}\">\
<xades:MimeType>{mime_type}</xades:MimeType></xades:DataObjectFormat>",
                reference.id
            ))
        })
        .collect();
    if !formats.is_empty() {
        signed.push_str(&format!(
            "<xades:SignedDataObjectProperties>{formats}</xades:SignedDataObjectProperties>"
        ));
    }

    let mut unsigned = String::new();
    if plan.timestamped {
        // The implicit data-selection form: no `xades:Include`, which means
        // the `ds:SignatureValue` element and is what the verifier reads
        // without having to resolve anything.
        unsigned.push_str(&format!(
            "<xades:SignatureTimeStamp><xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>",
            timestamp_placeholder(plan.signature_id)
        ));
    }
    if !plan.certificate_values.is_empty() {
        unsigned.push_str("<xades:CertificateValues>");
        for certificate in plan.certificate_values {
            unsigned.push_str(&format!(
                "<xades:EncapsulatedX509Certificate>{}</xades:EncapsulatedX509Certificate>",
                base64(certificate)
            ));
        }
        unsigned.push_str("</xades:CertificateValues>");
    }
    let unsigned = if unsigned.is_empty() {
        String::new()
    } else {
        format!(
            "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>{unsigned}\
</xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
        )
    };

    format!(
        "<ds:Object Id=\"xades-{}\">\
<xades:QualifyingProperties xmlns:xades=\"{XADES_NS}\" Target=\"#{}\">\
<xades:SignedProperties Id=\"{}\">{signed}</xades:SignedProperties>{unsigned}\
</xades:QualifyingProperties></ds:Object>",
        plan.signature_id, plan.signature_id, plan.signed_properties_id
    )
}

/// Render the `ds:Object` holding this signature's `es:SignatureProfile`.
///
/// The e-dossier format mandates that a document or frame signature reference
/// its own signature-profile object, and the reference-scope check enforces
/// it, so the object has to exist. Its content is metadata about the
/// signature, never about the signer: no name, no identifier, nothing derived
/// from the key.
pub(crate) fn render_signature_profile(signature_id: &str, namespace: &str) -> String {
    format!(
        "<ds:Object Id=\"profile-{signature_id}\">\
<es:SignatureProfile xmlns:es=\"{namespace}\" Id=\"sigprof-{signature_id}\">\
<es:Type>signature</es:Type>\
<es:Generator>openSzigno</es:Generator>\
</es:SignatureProfile></ds:Object>"
    )
}

/// The `Id` of the object [`render_signature_profile`] writes.
pub(crate) fn signature_profile_object_id(signature_id: &str) -> String {
    format!("profile-{signature_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan<'a>(references: &'a [PlannedReference], values: &'a [Vec<u8>]) -> QualifyingPlan<'a> {
        QualifyingPlan {
            signature_id: "sig-doc0",
            signed_properties_id: "signed-props-sig-doc0",
            signing_time: "2026-01-01T00:00:00Z",
            certificate: b"certificate",
            references,
            certificate_values: values,
            timestamped: false,
        }
    }

    #[test]
    fn the_signed_properties_carry_the_time_and_the_certificate_digest() {
        let references = vec![
            PlannedReference::to("ref-0", "obj0").with_mime_type("text/plain".to_owned()),
            PlannedReference::signed_properties("ref-1", "signed-props-sig-doc0"),
        ];
        let xml = render_qualifying_properties(&plan(&references, &[]));
        assert!(xml.contains("<xades:SigningTime>2026-01-01T00:00:00Z</xades:SigningTime>"));
        assert!(xml.contains("SigningCertificateV2"));
        assert!(xml.contains(&base64(&certificate_digest(b"certificate"))));
        assert!(xml.contains("<xades:MimeType>text/plain</xades:MimeType>"));
        assert!(xml.contains("ObjectReference=\"#ref-0\""));
        // Nothing unsigned was asked for, so nothing unsigned is written.
        assert!(!xml.contains("UnsignedProperties"));
        assert!(xml.contains("Id=\"signed-props-sig-doc0\""));
    }

    #[test]
    fn evidence_goes_in_the_unsigned_half_only() {
        let references = vec![PlannedReference::to("ref-0", "obj0")];
        let mut plan = plan(&references, &[]);
        let values = vec![b"issuer".to_vec()];
        plan.certificate_values = &values;
        plan.timestamped = true;
        let xml = render_qualifying_properties(&plan);
        let unsigned = xml
            .split_once("<xades:UnsignedProperties>")
            .expect("the unsigned half is written")
            .1;
        assert!(unsigned.contains("EncapsulatedX509Certificate"));
        assert!(unsigned.contains(&timestamp_placeholder("sig-doc0")));
        // No `xades:Include`: the implicit selection is the signature value.
        assert!(!xml.contains("xades:Include"));
        // A reference with no declared type gets no DataObjectFormat.
        assert!(!xml.contains("DataObjectFormat"));
    }

    #[test]
    fn the_signature_profile_object_is_named_after_the_signature() {
        let xml = render_signature_profile("sig-dossier", "urn:example");
        assert!(xml.contains(&format!(
            "Id=\"{}\"",
            signature_profile_object_id("sig-dossier")
        )));
        assert!(xml.contains("xmlns:es=\"urn:example\""));
        assert!(xml.contains("es:SignatureProfile"));
    }
}
