//! ETSI TS 119 612 trusted lists.
//!
//! A trusted list is how the EU says which CAs are entitled to issue
//! qualified certificates, and *when* each of them was. Reading one gives two
//! things a `--trust-store` directory cannot: trust anchors whose provenance
//! is a published national list rather than a human's copy-and-paste, and the
//! qualified determination itself.
//!
//! # What is read
//!
//! For every `TSPService` whose `ServiceTypeIdentifier` is a CA issuing
//! qualified certificates (`.../Svctype/CA/QC`) or a qualified timestamping
//! authority (`.../Svctype/TSA/QTST`), every X.509 certificate in the service
//! digital identity becomes a trust anchor, carrying the service's status
//! timeline: the current `ServiceStatus` with its `StatusStartingTime`, plus
//! every `ServiceHistoryInstance`. A path that ends at such an anchor is
//! trusted only if the service was granted **at the validation time**, which
//! is what makes a signature made while a CA was supervised still verify after
//! that CA was withdrawn, and a signature made after the withdrawal not.
//!
//! A `DigitalId` that carries only an `X509SubjectName` or an `X509SKI` — both
//! common in real lists — is **not** an anchor: it identifies a certificate
//! without supplying one, and this build will not go looking. Only
//! `X509Certificate` produces an anchor. Since M3 the other two forms are
//! still *read*, as service identities that can corroborate the qualified
//! status of a chain some other anchor already validated: an `X509SKI` is
//! matched against a certificate's `subjectKeyIdentifier` and an
//! `X509SubjectName` against its **DER-encoded** subject, never by string
//! comparison. Both are deliberately weaker than a certificate identity — a
//! key identifier and a name are things a CA wrote down, not proof of
//! possession — so they may decide `qualified`, and can never grant trust.
//!
//! # What is deliberately not done
//!
//! Nothing is fetched. A trusted list is a file the operator downloaded and
//! pinned, and `docs/trust.md` describes that workflow. Scheme-level
//! `Qualifications` extensions, which refine qualified status per certificate
//! subset, are read far enough to be *reported* as unprocessed and are never
//! used to widen a determination.
//!
//! The module is split by what each part does: `parse` reads the XML — the
//! list frame, the service records and their digital identities, and the
//! pointers to other lists; `services` evaluates the status timeline and the
//! pre-eIDAS rules; and `qualified` decides the qualified status of a
//! validated chain. What stays here is the public API and the verification of
//! the list's own XMLDSig signature.

mod parse;
mod qualified;
mod services;

pub use parse::{TrustList, load};
pub(crate) use qualified::qualification;
pub use services::{
    EIDAS_APPLICATION_DATE, GRANTED_STATUSES, PRE_EIDAS_GRANTED_STATUSES, ServiceRecord,
    ServiceStatusEntry, ServiceType,
};

use parse::{attribute_id, decode_base64, ds_child, text};

use openszigno_core::XmlSource;
use openszigno_core::roxmltree::Node;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::c14n::{C14nAlgorithm, C14nBackend, NodeSet};
use crate::certs::{CertificateSource, ParsedCertificate};
use crate::codes::{Check, CheckCode};
use crate::policy::{Digest, SignatureScheme, Transform};

/// The largest trusted list this build will parse.
pub const MAX_TRUST_LIST_BYTES: usize = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// The list's own XMLDSig signature
// ---------------------------------------------------------------------------

/// Verify the enveloped XMLDSig signature over a trusted list.
///
/// This is the same core the dossier pipeline uses — the same canonicalization
/// backend, the same pinned algorithm and transform allowlists, the same
/// signature verification — applied to a document whose placement rules are
/// TS 119 612's rather than the e-dossier's: exactly one `ds:Signature` as a
/// child of the list element, covering the whole document with the
/// enveloped-signature transform.
pub(super) fn verify_list_signature(
    source: &XmlSource,
    root: Node<'_, '_>,
    signers: &[Vec<u8>],
    backend: &dyn C14nBackend,
) -> Check {
    let invalid = |message: &str| Check::failed(CheckCode::TrustListSignatureInvalid, message);

    // Any one of the supplied certificates verifying is enough: a scheme
    // operator may publish several, and a verifier cannot know which of them
    // signed the copy in hand.
    let candidates: Vec<ParsedCertificate> = signers
        .iter()
        .filter_map(|der| ParsedCertificate::from_der(der, CertificateSource::TrustStore))
        .collect();
    if candidates.is_empty() {
        return invalid("no supplied trust-list signer is a usable X.509 certificate");
    }
    let signatures: Vec<Node<'_, '_>> = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(openszigno_core::XMLDSIG_NAMESPACE)
                && node.tag_name().name() == "Signature"
        })
        .collect();
    let [signature] = signatures.as_slice() else {
        return invalid("the trusted list does not carry exactly one ds:Signature of its own");
    };
    let Some(signed_info) = ds_child(*signature, "SignedInfo") else {
        return invalid("the trusted list's signature has no ds:SignedInfo");
    };
    let Some(signature_value) = ds_child(*signature, "SignatureValue") else {
        return invalid("the trusted list's signature has no ds:SignatureValue");
    };

    let Some(c14n) = ds_child(signed_info, "CanonicalizationMethod")
        .and_then(|node| node.attribute("Algorithm"))
        .and_then(C14nAlgorithm::from_uri)
    else {
        return invalid(
            "the trusted list's signature names a canonicalization method outside the allowlist",
        );
    };
    let Some(scheme) = ds_child(signed_info, "SignatureMethod")
        .and_then(|node| node.attribute("Algorithm"))
        .and_then(SignatureScheme::from_signature_uri)
        .filter(|scheme| !scheme.is_legacy())
    else {
        return invalid(
            "the trusted list's signature names a signature method outside the allowlist",
        );
    };

    // Every reference must verify. A trusted list whose signature covers only
    // part of itself is a trusted list an attacker can extend.
    let references: Vec<Node<'_, '_>> = signed_info
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(openszigno_core::XMLDSIG_NAMESPACE)
                && node.tag_name().name() == "Reference"
        })
        .collect();
    if references.is_empty() {
        return invalid("the trusted list's ds:SignedInfo carries no ds:Reference");
    }
    let mut covers_document = false;
    for reference in references {
        match check_reference(source, root, *signature, reference, backend) {
            Ok(covers_list) => covers_document |= covers_list,
            Err(message) => return invalid(&message),
        }
    }
    if !covers_document {
        return invalid(
            "the trusted list's signature does not cover the whole list; a partial reference set would leave the service entries unprotected",
        );
    }

    let Ok(canonical) = backend.canonicalize(
        source.text(),
        &NodeSet::subtree(signed_info).without_comments(),
        c14n,
        &[],
    ) else {
        return invalid("the trusted list's ds:SignedInfo could not be canonicalized");
    };
    let Some(value) = decode_base64(&text(signature_value)) else {
        return invalid("the trusted list's ds:SignatureValue is not Base64");
    };
    let verified = candidates.iter().any(|candidate| {
        crate::certs::verify_with_spki(&candidate.certificate, scheme, &canonical, &value, false)
            .is_ok()
    });
    if verified {
        return Check::passed(
            CheckCode::TrustListSignatureOk,
            format!(
                "the trusted list's own XMLDSig signature verified against one of {} supplied signer certificate(s)",
                candidates.len()
            ),
        );
    }
    invalid(
        "the trusted list's own XMLDSig signature did not verify against any supplied signer certificate",
    )
}

/// Verify one reference of the trusted list's signature.
///
/// Returns whether this reference covers the whole list.
///
/// TS 119 612 annex B.1.0 rule 2 asks for "a `ds:Reference` element with the
/// URI attribute set to a value referencing the `TrustServiceStatusList`
/// element enveloping the digital signature itself", which both the empty URI
/// and a same-document `#Id` naming the list element satisfy. Both live EU
/// lists write the empty URI, but a list that names the element by its `Id` is
/// covering exactly as much, so it counts too.
fn check_reference(
    source: &XmlSource,
    root: Node<'_, '_>,
    signature: Node<'_, '_>,
    reference: Node<'_, '_>,
    backend: &dyn C14nBackend,
) -> Result<bool, String> {
    let uri = reference.attribute("URI").unwrap_or("");
    let empty_uri = uri.is_empty();
    let apex = if empty_uri {
        root.parent().unwrap_or(root)
    } else {
        let id = uri
            .strip_prefix('#')
            .ok_or_else(|| "the trusted list's signature names an external reference".to_owned())?;
        let mut matches = root
            .descendants()
            .filter(|node| node.is_element() && attribute_id(*node) == Some(id));
        let found = matches
            .next()
            .ok_or_else(|| "a reference in the trusted list resolves to nothing".to_owned())?;
        if matches.next().is_some() {
            return Err(
                "a reference in the trusted list resolves to more than one node".to_owned(),
            );
        }
        found
    };
    let covers_list = empty_uri || apex == root;

    let mut set = if empty_uri {
        NodeSet::document(apex)
    } else {
        NodeSet::subtree(apex)
    }
    .without_comments();
    let mut algorithm = C14nAlgorithm::Inclusive { comments: false };
    let mut enveloped = false;
    if let Some(transforms) = ds_child(reference, "Transforms") {
        for transform in transforms.children().filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(openszigno_core::XMLDSIG_NAMESPACE)
                && node.tag_name().name() == "Transform"
        }) {
            let uri = transform.attribute("Algorithm").unwrap_or_default();
            match Transform::from_uri(uri) {
                Some(Transform::EnvelopedSignature) => {
                    set.exclude(signature);
                    enveloped = true;
                }
                Some(Transform::Canonicalization(selected)) => algorithm = selected,
                // Base64 has no meaning over an element node set here, and
                // everything else is outside the allowlist on purpose.
                _ => {
                    return Err(
                        "the trusted list's signature uses a transform outside the allowlist"
                            .to_owned(),
                    );
                }
            }
        }
    }
    if covers_list && !enveloped {
        return Err(
            "the trusted list's signature covers the whole document without the enveloped-signature transform, which cannot verify"
                .to_owned(),
        );
    }

    let Some(digest) = ds_child(reference, "DigestMethod")
        .and_then(|node| node.attribute("Algorithm"))
        .and_then(Digest::from_digest_uri)
        .filter(|digest| !digest.is_legacy())
    else {
        return Err("the trusted list's signature names a digest outside the allowlist".to_owned());
    };
    let expected = ds_child(reference, "DigestValue")
        .and_then(|node| decode_base64(&text(node)))
        .ok_or_else(|| "a reference digest in the trusted list is not Base64".to_owned())?;

    let octets = backend
        .canonicalize(source.text(), &set, algorithm, &[])
        .map_err(|_| "a reference in the trusted list could not be canonicalized".to_owned())?;
    let computed = match digest {
        Digest::Sha1 => Sha1::digest(&octets).to_vec(),
        Digest::Sha256 => Sha256::digest(&octets).to_vec(),
        Digest::Sha384 => Sha384::digest(&octets).to_vec(),
        Digest::Sha512 => Sha512::digest(&octets).to_vec(),
    };
    if computed != expected {
        return Err("a reference digest in the trusted list does not match".to_owned());
    }
    Ok(covers_list)
}
