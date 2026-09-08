//! Signing a dossier: enveloped XMLDSig with the XAdES signed properties the
//! e-dossier reference-scope rules require.
//!
//! This module takes the bytes of a dossier, a [`Signer`], and optionally a
//! callback that turns a digest into an RFC 3161 token, and returns the bytes
//! of a signed dossier. It reads no file, opens no socket and consults no
//! clock: the signing time arrives already formatted, the key lives behind the
//! `Signer` seam, and the timestamp authority is somebody else's socket.
//!
//! # Signing is not verification
//!
//! Nothing here checks anything. A dossier this module returns carries a
//! signature made with the key the caller supplied over the elements the
//! format mandates; whether that signature verifies, whether the certificate
//! chains anywhere, and whether any of it means anything are questions only
//! `openszigno verify` answers, against trust material the caller supplies.
//!
//! # The module map
//!
//! | Module | What it owns |
//! | :--- | :--- |
//! | this one | The driver: what to sign, where the element goes, and the three passes that fill it in. |
//! | `dsig` | `ds:SignedInfo`, its references, and the canonicalized octets each one digests. |
//! | `xades` | `xades:QualifyingProperties`: the signed properties, and the evidence in the unsigned half. |
//! | `signer` | The [`Signer`] trait and [`SoftwareSigner`], the local-key implementation. |
//! | `tsa` | RFC 3161 requests and responses, as bytes in and bytes out. |
//!
//! # How a signature is filled in
//!
//! The element is written with placeholders and then completed in three
//! passes, because each stage's input only exists once the previous one is in
//! the document:
//!
//! 1. every reference digest, over the working document that now holds the
//!    signature skeletons;
//! 2. every `ds:SignatureValue`, over the canonicalized `ds:SignedInfo` that
//!    now holds the digests;
//! 3. every `xades:SignatureTimeStamp`, over the canonicalized
//!    `ds:SignatureValue` that now holds the signature.
//!
//! Each pass may fill several signatures at once, which is sound only because
//! no signature this module writes ever contains another: a document
//! signature's references name its own document's profile, that document's
//! payload object, and two objects inside itself.

mod dsig;
mod error;
mod signer;
mod tsa;
mod xades;

use openszigno_core::{Document, ParseOptions};

pub use error::{SignError, SignErrorCode};
pub use signer::{SignatureAlgorithm, Signer, SoftwareSigner, parse_certificates};
pub use tsa::{TIMESTAMP_QUERY_TYPE, TIMESTAMP_REPLY_TYPE, timestamp_request, timestamp_token};

use dsig::{PlannedReference, Working, digest_placeholder, value_placeholder};
use xades::{QualifyingPlan, timestamp_placeholder};

/// Which signature the caller wants, and therefore which elements it covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignScope {
    /// One signature per selected document, inside that `es:Document`,
    /// covering its `es:DocumentProfile` and its payload `ds:Object`.
    Document,
    /// One signature on the dossier itself, covering the
    /// `es:DossierProfile` and every document through `es:Documents`.
    Dossier,
}

impl SignScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Dossier => "dossier",
        }
    }
}

/// What to sign, and what to write alongside the signature.
#[derive(Clone, Debug)]
pub struct SignRequest {
    pub scope: SignScope,
    /// `--document` selectors: `#<index>`, or a document's `object_ref`. An
    /// empty list means every modelled document, and is meaningless for
    /// [`SignScope::Dossier`], which signs the dossier as a whole.
    pub documents: Vec<String>,
    /// The `xades:SigningTime` to write, RFC 3339 UTC seconds, formatted by
    /// the caller. This crate reads no clock.
    pub signing_time: String,
    /// Certificates for `xades:CertificateValues`: the signer's issuing CAs
    /// and the timestamp authority's, so a verifier can build both paths
    /// without being handed them separately.
    pub certificate_values: Vec<Vec<u8>>,
}

/// One signature that was written.
#[derive(Clone, Debug)]
pub struct WrittenSignature {
    pub id: String,
    pub scope: SignScope,
    /// The index of the document the signature sits in, for document scope.
    pub document_index: Option<usize>,
    pub algorithm: SignatureAlgorithm,
    pub signing_time: String,
    /// Whether an `xades:SignatureTimeStamp` was written. It says a token was
    /// obtained and embedded, never that it was verified.
    pub timestamped: bool,
}

/// The signed dossier.
pub struct SignedDossier {
    pub bytes: Vec<u8>,
    pub signatures: Vec<WrittenSignature>,
}

/// Turn a digest into an RFC 3161 `TimeStampToken`, however the caller does
/// that. The error text reaches the report as the reason a `tsa_failed`
/// refusal names.
pub type TimestampFn<'a> = dyn FnMut(&[u8]) -> Result<Vec<u8>, String> + 'a;

/// One signature to write, resolved against the dossier.
struct Plan {
    id: String,
    scope: SignScope,
    document_index: Option<usize>,
    /// Where the `ds:Signature` element goes, as a byte offset into the
    /// working text.
    insert_at: usize,
    references: Vec<PlannedReference>,
    element: String,
}

/// Sign `bytes`, and return the signed dossier.
///
/// `timestamp`, when given, is called once per signature with the SHA-256
/// digest of the canonicalized `ds:SignatureValue` and must return the DER of
/// an RFC 3161 `TimeStampToken`.
pub fn sign(
    bytes: &[u8],
    options: &ParseOptions,
    request: &SignRequest,
    signer: &dyn Signer,
    mut timestamp: Option<&mut TimestampFn<'_>>,
) -> Result<SignedDossier, SignError> {
    let dossier = openszigno_core::parse_with_options(bytes, options)
        .map_err(|error| SignError::failed(error.message().to_owned()))?;
    let text = normalise_declaration(
        openszigno_core::XmlSource::decode(bytes, &options.limits)
            .map_err(|error| SignError::failed(error.message().to_owned()))?
            .text(),
    );

    let working = Working::parse(&text)?;
    let plans = working.with_tree(|lookup| {
        refuse_unsafe_placement(lookup, request.scope)?;
        let targets = targets(&dossier, request)?;
        plan_signatures(
            lookup,
            &dossier,
            request,
            signer,
            &targets,
            timestamp.is_some(),
        )
    })?;

    let mut text = insert_signatures(text, &plans);
    text = fill_digests(&text, &plans)?;
    text = fill_signature_values(&text, &plans, signer)?;
    if let Some(callback) = timestamp.as_deref_mut() {
        text = fill_timestamps(&text, &plans, callback)?;
    }

    Ok(SignedDossier {
        signatures: plans
            .iter()
            .map(|plan| WrittenSignature {
                id: plan.id.clone(),
                scope: plan.scope,
                document_index: plan.document_index,
                algorithm: signer.algorithm(),
                signing_time: request.signing_time.clone(),
                timestamped: timestamp.is_some(),
            })
            .collect(),
        bytes: text.into_bytes(),
    })
}

/// The XML declaration says UTF-8, because that is what is written.
///
/// A dossier declared ISO-8859-2 is decoded to UTF-8 before anything is
/// signed, so writing the original declaration back would make the file lie
/// about its own bytes. Re-encoding changes no signature already in the file:
/// canonical XML is UTF-8 whatever the source encoding was, so every existing
/// digest is computed over exactly the same octets as before.
fn normalise_declaration(text: &str) -> String {
    let Some(end) = text.find("?>") else {
        return text.to_owned();
    };
    let declaration = &text[..end];
    if !declaration.starts_with("<?xml") {
        return text.to_owned();
    }
    let Some(start) = declaration.find("encoding=\"") else {
        return text.to_owned();
    };
    let value_start = start + "encoding=\"".len();
    let Some(value_end) = declaration[value_start..].find('"') else {
        return text.to_owned();
    };
    let value_end = value_start + value_end;
    if declaration[value_start..value_end].eq_ignore_ascii_case("UTF-8") {
        return text.to_owned();
    }
    format!("{}UTF-8{}", &text[..value_start], &text[value_end..])
}

/// The documents to sign, in source order.
fn targets<'a>(
    dossier: &'a openszigno_core::Dossier,
    request: &SignRequest,
) -> Result<Vec<&'a Document>, SignError> {
    if request.scope == SignScope::Dossier {
        return Ok(Vec::new());
    }
    if request.documents.is_empty() {
        if dossier.documents.is_empty() {
            return Err(SignError::new(
                SignErrorCode::DocumentNotSignable,
                "the dossier holds no document with a profile, so there is nothing to sign",
            ));
        }
        return Ok(dossier.documents.iter().collect());
    }
    let mut selected: Vec<&Document> = Vec::new();
    for selector in &request.documents {
        let found = resolve_selector(dossier, selector)?;
        if !selected
            .iter()
            .any(|document| document.index == found.index)
        {
            selected.push(found);
        }
    }
    selected.sort_by_key(|document| document.index);
    Ok(selected)
}

/// One `--document` selector, resolved exactly as `extract` resolves it.
fn resolve_selector<'a>(
    dossier: &'a openszigno_core::Dossier,
    selector: &str,
) -> Result<&'a Document, SignError> {
    let not_found = || {
        SignError::new(
            SignErrorCode::DocumentNotFound,
            "a --document selector matches no document in this dossier",
        )
    };
    if let Some(index) = selector.strip_prefix('#') {
        let index: usize = index.parse().map_err(|_| not_found())?;
        return dossier
            .documents
            .iter()
            .find(|document| document.index == index)
            .ok_or_else(not_found);
    }
    dossier
        .documents
        .iter()
        .find(|document| document.object_ref == selector)
        .ok_or_else(not_found)
}

/// Refuse to write into a dossier where doing so would invalidate what is
/// already there.
///
/// Adding a `ds:Signature` inside an `es:Document` changes the canonical form
/// of `es:Documents`, so anything already covering that element — a dossier
/// signature, or a dossier-level `es:TimeStamp` — would stop verifying. And
/// any existing signature with a `URI=""` reference covers the whole document,
/// so nothing may be added anywhere. In both cases the honest answer is to
/// refuse rather than to hand back a dossier whose older signatures this run
/// quietly broke. See the limitation in `docs/architecture.md`.
fn refuse_unsafe_placement(lookup: &dsig::Lookup<'_>, scope: SignScope) -> Result<(), SignError> {
    let already_signed = |reason: &str| {
        Err(SignError::new(
            SignErrorCode::DocumentAlreadySigned,
            format!("this dossier cannot have a signature added to it: {reason}"),
        ))
    };
    for signature in lookup.signatures() {
        if lookup.has_whole_document_reference(signature) {
            return already_signed(
                "an existing signature references the whole document, so adding anything to it would break that signature",
            );
        }
    }
    if scope == SignScope::Document && lookup.has_dossier_level_cover() {
        return already_signed(
            "an existing dossier-level signature or timestamp covers es:Documents, so a new signature inside a document would break it",
        );
    }
    Ok(())
}

/// Resolve every signature this run writes: its identifiers, its references,
/// and where the element goes.
fn plan_signatures(
    lookup: &dsig::Lookup<'_>,
    dossier: &openszigno_core::Dossier,
    request: &SignRequest,
    signer: &dyn Signer,
    targets: &[&Document],
    timestamped: bool,
) -> Result<Vec<Plan>, SignError> {
    let namespace = dossier.namespace.as_str();
    let mut plans = Vec::new();
    match request.scope {
        SignScope::Dossier => {
            let profile = lookup.dossier_child_id(namespace, "DossierProfile")?;
            let documents = lookup.dossier_child_id(namespace, "Documents")?;
            plans.push(build_plan(
                lookup,
                PlanSpec {
                    id: "sig-dossier".to_owned(),
                    scope: SignScope::Dossier,
                    document_index: None,
                    insert_at: lookup.insert_offset(lookup.root())?,
                    covered: vec![
                        ("dossier-profile", profile, None),
                        ("documents", documents, None),
                    ],
                    timestamped,
                },
                request,
                signer,
                namespace,
            )?);
        }
        SignScope::Document => {
            for document in targets {
                let id = format!("sig-doc{}", document.index);
                let node = lookup.by_id(&document.object_ref).ok_or_else(|| {
                    SignError::new(
                        SignErrorCode::DocumentNotSignable,
                        format!(
                            "document {} has no payload ds:Object to sign",
                            document.index
                        ),
                    )
                })?;
                let container = node
                    .parent()
                    .filter(|parent| parent.is_element())
                    .ok_or_else(|| {
                        SignError::new(
                            SignErrorCode::DocumentNotSignable,
                            format!("document {} has no es:Document element", document.index),
                        )
                    })?;
                let profile = lookup.document_profile_id(container).ok_or_else(|| {
                    SignError::new(
                        SignErrorCode::DocumentNotSignable,
                        format!(
                            "document {} has no es:DocumentProfile with an Id, so nothing can reference it",
                            document.index
                        ),
                    )
                })?;
                plans.push(build_plan(
                    lookup,
                    PlanSpec {
                        id,
                        scope: SignScope::Document,
                        document_index: Some(document.index),
                        insert_at: lookup.insert_offset(container)?,
                        covered: vec![
                            (
                                "object",
                                document.object_ref.clone(),
                                Some(document.mime_type.essence()),
                            ),
                            ("document-profile", profile, None),
                        ],
                        timestamped,
                    },
                    request,
                    signer,
                    namespace,
                )?);
            }
        }
    }
    Ok(plans)
}

/// What one signature covers, before its XML exists.
struct PlanSpec {
    id: String,
    scope: SignScope,
    document_index: Option<usize>,
    insert_at: usize,
    /// The elements the e-dossier format mandates this signature cover, as
    /// `(reference name, target Id, declared media type)`.
    covered: Vec<(&'static str, String, Option<String>)>,
    timestamped: bool,
}

/// Assemble one signature's references and its XML.
fn build_plan(
    lookup: &dsig::Lookup<'_>,
    spec: PlanSpec,
    request: &SignRequest,
    signer: &dyn Signer,
    namespace: &str,
) -> Result<Plan, SignError> {
    let PlanSpec {
        id,
        scope,
        document_index,
        insert_at,
        covered,
        timestamped,
    } = spec;
    let signed_properties_id = format!("signed-props-{id}");
    let profile_object_id = xades::signature_profile_object_id(&id);
    for taken in [&signed_properties_id, &profile_object_id] {
        if lookup.by_id(taken).is_some() {
            return Err(SignError::failed(
                "an identifier this signature needs is already used in the dossier",
            ));
        }
    }
    if lookup.by_id(&id).is_some() {
        return Err(SignError::new(
            SignErrorCode::DocumentAlreadySigned,
            "a signature with the identifier this run would write already exists",
        ));
    }

    let mut references = Vec::new();
    for (name, target, mime_type) in covered {
        let reference = PlannedReference::to(&format!("ref-{id}-{name}"), &target);
        references.push(match mime_type {
            Some(value) => reference.with_mime_type(value),
            None => reference,
        });
    }
    references.push(PlannedReference::to(
        &format!("ref-{id}-signature-profile"),
        &profile_object_id,
    ));
    references.push(PlannedReference::signed_properties(
        &format!("ref-{id}-signed-properties"),
        &signed_properties_id,
    ));

    let mut element = format!(
        "<ds:Signature xmlns:ds=\"{}\" Id=\"{id}\">",
        dsig::XMLDSIG_NS
    );
    element.push_str(&dsig::render_signed_info(
        &id,
        signer.algorithm(),
        &references,
        signer.certificate(),
    ));
    element.push_str(&xades::render_signature_profile(&id, namespace));
    element.push_str(&xades::render_qualifying_properties(&QualifyingPlan {
        signature_id: &id,
        signed_properties_id: &signed_properties_id,
        signing_time: &request.signing_time,
        certificate: signer.certificate(),
        references: &references,
        certificate_values: &request.certificate_values,
        timestamped,
    }));
    element.push_str("</ds:Signature>");

    Ok(Plan {
        id,
        scope,
        document_index,
        insert_at,
        references,
        element,
    })
}

/// Splice every signature skeleton into the text, last offset first so the
/// offsets of the ones still to come stay valid.
fn insert_signatures(text: String, plans: &[Plan]) -> String {
    let mut ordered: Vec<&Plan> = plans.iter().collect();
    ordered.sort_by_key(|plan| std::cmp::Reverse(plan.insert_at));
    let mut text = text;
    for plan in ordered {
        text.insert_str(plan.insert_at, &plan.element);
    }
    text
}

/// Pass one: every reference digest, over the document the signatures now sit
/// in.
fn fill_digests(text: &str, plans: &[Plan]) -> Result<String, SignError> {
    let working = Working::parse(text)?;
    let filled = working.with_tree(|lookup| {
        let mut replacements = Vec::new();
        for plan in plans {
            for reference in &plan.references {
                let target = reference.uri.trim_start_matches('#');
                let octets = lookup.canonical_by_id(target)?;
                replacements.push((
                    digest_placeholder(&reference.id),
                    dsig::digest_value(&octets),
                ));
            }
        }
        Ok(replacements)
    })?;
    Ok(replace_all(working.text(), &filled))
}

/// Pass two: every `ds:SignatureValue`, over the canonicalized
/// `ds:SignedInfo` that now carries the digests.
fn fill_signature_values(
    text: &str,
    plans: &[Plan],
    signer: &dyn Signer,
) -> Result<String, SignError> {
    let working = Working::parse(text)?;
    let octets = working.with_tree(|lookup| {
        plans
            .iter()
            .map(|plan| Ok((plan.id.clone(), lookup.canonical_signed_info(&plan.id)?)))
            .collect::<Result<Vec<_>, SignError>>()
    })?;
    let mut replacements = Vec::new();
    for (id, octets) in octets {
        // A hash-only backend never sees the octets, only their digest; a
        // local key signs the octets themselves. The signer decides which.
        let signature = if signer.prefers_digest() {
            signer.sign_digest(&dsig::digest(&octets))?
        } else {
            signer.sign_bytes(&octets)?
        };
        replacements.push((value_placeholder(&id), dsig::base64(&signature)));
    }
    Ok(replace_all(working.text(), &replacements))
}

/// Pass three: every `xades:SignatureTimeStamp`, over the canonicalized
/// `ds:SignatureValue` that now carries the signature.
fn fill_timestamps(
    text: &str,
    plans: &[Plan],
    timestamp: &mut TimestampFn<'_>,
) -> Result<String, SignError> {
    let working = Working::parse(text)?;
    let octets = working.with_tree(|lookup| {
        plans
            .iter()
            .map(|plan| Ok((plan.id.clone(), lookup.canonical_signature_value(&plan.id)?)))
            .collect::<Result<Vec<_>, SignError>>()
    })?;
    let mut replacements = Vec::new();
    for (id, octets) in octets {
        let response = timestamp(&octets).map_err(|reason| {
            SignError::new(
                SignErrorCode::TsaFailed,
                format!("the timestamp authority could not be used: {reason}"),
            )
        })?;
        let token = tsa::timestamp_token(&response, &octets)?;
        replacements.push((timestamp_placeholder(&id), dsig::base64(&token)));
    }
    Ok(replace_all(working.text(), &replacements))
}

/// Replace each placeholder with its value, once.
fn replace_all(text: &str, replacements: &[(String, String)]) -> String {
    let mut text = text.to_owned();
    for (placeholder, value) in replacements {
        text = text.replace(placeholder.as_str(), value);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declaration_is_rewritten_only_when_it_names_another_encoding() {
        let utf8 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a/>";
        assert_eq!(normalise_declaration(utf8), utf8);
        assert_eq!(
            normalise_declaration("<?xml version=\"1.0\" encoding=\"ISO-8859-2\"?><a/>"),
            utf8
        );
        // No declaration, or none this shape, is left exactly as it was.
        assert_eq!(normalise_declaration("<a/>"), "<a/>");
        assert_eq!(
            normalise_declaration("<?xml version=\"1.0\"?><a/>"),
            "<?xml version=\"1.0\"?><a/>"
        );
    }

    #[test]
    fn scope_names_are_the_ones_the_report_uses() {
        assert_eq!(SignScope::Document.as_str(), "document");
        assert_eq!(SignScope::Dossier.as_str(), "dossier");
    }
}
