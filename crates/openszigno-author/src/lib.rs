//! Deterministic authoring of Microsec e-Szignó dossiers.
//!
//! This crate is the writer side of openSzigno. It builds an unsigned
//! `es:Dossier` in the default e-Szignó 3.0 namespace, in the shape
//! [`openszigno_core`] parses, and it does almost nothing else: it signs
//! nothing, reads no file, and consults no clock. A dossier it produces
//! carries no signature and is not evidence of anything.
//!
//! The one exception is the `encrypt` transform: when a [`DossierSpec`]
//! names recipients, a document's payload is written as a CMS
//! `EnvelopedData` addressed to them, which is what
//! `openszigno extract --decrypt-key` reads back. Encrypting says who can
//! read a document and nothing about who wrote it.
//!
//! Two properties are load-bearing:
//!
//! - **Determinism.** The same [`DossierSpec`] always renders the same bytes,
//!   **unless it asks for encryption**. Element order, indentation, and
//!   identifiers are fixed, the identifiers are positional (`obj0`,
//!   `profile0`, ...), and the creation date comes from the caller. A content
//!   key, an initialisation vector, and key-transport padding must be
//!   unpredictable, so a spec carrying an [`Encryption`] renders different
//!   bytes on every run by design.
//! - **Readability by the reader.** Every bound [`Limits`] places on a dossier
//!   is checked while building, and every document title is checked against
//!   the rules `openszigno extract` applies before it writes a file, so a
//!   dossier this crate returns is one the rest of the tool can list, decode,
//!   and extract.

mod archive;
mod encrypt;
mod error;
mod mime;
mod render;
pub mod sign;
mod title;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use openszigno_core::{Limits, MimeType};
use serde::Serialize;
use unicode_normalization::UnicodeNormalization;

pub use encrypt::{Encryption, KeyTransport, Recipient};
pub use error::{Error, ErrorCode};
pub use mime::{NESTED_DOSSIER_EXTENSION, NESTED_DOSSIER_MEDIA_TYPE, NESTED_DOSSIER_SUBTYPE};
pub use render::{DOCUMENT_CATEGORY, DOSSIER_CATEGORY};
pub use title::{TitleRejection, check_title, declarable_extension};

/// The longest dossier title accepted. It is metadata, not a filename, so the
/// filename rules do not apply to it; only the XML ones do.
const MAX_DOSSIER_TITLE_BYTES: usize = 1024;

/// One document to place in a dossier.
#[derive(Clone, Debug)]
pub struct DocumentSpec {
    /// The `es:Title`, which is also the name `extract` writes the payload
    /// under. It must pass [`check_title`].
    pub title: String,
    /// The `type/subtype` to declare. `None` derives it from the title's
    /// extension, and is refused when nothing is registered for it.
    pub media_type: Option<String>,
    /// The document's bytes, exactly as they must come back out.
    pub bytes: Vec<u8>,
    /// Store the payload as `zip -> base64` instead of `base64`.
    pub compress: bool,
    /// Encrypt the payload for the dossier's recipients, when it has any.
    ///
    /// Set per document rather than per dossier because an embedded dossier
    /// is written in the clear: see [`DossierSpec::encryption`].
    pub encrypt: bool,
}

/// The dossier to build.
#[derive(Clone, Debug)]
pub struct DossierSpec {
    /// The `es:Title` of the dossier itself.
    pub title: String,
    /// The creation date written for the dossier and for every document, as
    /// the caller formatted it. This crate never reads a clock.
    pub created: String,
    /// The documents, in the order they are written.
    pub documents: Vec<DocumentSpec>,
    /// Who every [`DocumentSpec::encrypt`] document is encrypted for, or
    /// `None` to write every payload in the clear.
    ///
    /// A spec that carries this renders different bytes on every run; see the
    /// determinism note on this crate.
    pub encryption: Option<Encryption>,
}

/// One document as it was written.
#[derive(Clone, Debug, Serialize)]
pub struct BuiltDocument {
    pub index: usize,
    pub title: String,
    pub mime_type: MimeType,
    /// The declared `SourceSize`, which is the decoded length.
    pub source_size: u64,
    pub transforms: Vec<String>,
    /// Whether the declared type marks this document as an embedded dossier,
    /// under the same rule the reader applies.
    pub nested_dossier: bool,
    /// Whether the payload was written as a CMS `EnvelopedData`, so that only
    /// a recipient's private key can read it back. It says nothing about who
    /// wrote the document.
    pub encrypted: bool,
    /// The `ds:Object` `Id` the profile points at, which is also the
    /// `extract --document` selector for it.
    pub object_ref: String,
}

/// A finished dossier: the bytes to write, and what went into them.
#[derive(Clone, Debug)]
pub struct BuiltDossier {
    pub bytes: Vec<u8>,
    pub documents: Vec<BuiltDocument>,
}

/// The same rule [`openszigno_core`] applies when it decides that a document
/// holds another dossier.
fn is_nested_dossier(mime: &MimeType) -> bool {
    mime.essence().eq_ignore_ascii_case(&format!(
        "{NESTED_DOSSIER_MEDIA_TYPE}/{NESTED_DOSSIER_SUBTYPE}"
    )) || mime
        .extension
        .as_deref()
        .is_some_and(|extension| extension.eq_ignore_ascii_case(NESTED_DOSSIER_EXTENSION))
}

/// Check the dossier's own title: it is XML text, so it may hold anything a
/// document title may hold plus the filename-only refusals, but it may not be
/// empty and may not carry a control character.
fn check_dossier_title(title: &str) -> Result<(), Error> {
    let unusable = |reason: &str| {
        Error::new(
            ErrorCode::InvalidDossierTitle,
            format!("the dossier title {reason}"),
        )
    };
    if title.trim().is_empty() {
        return Err(unusable("must not be empty"));
    }
    if title.len() > MAX_DOSSIER_TITLE_BYTES {
        return Err(unusable(&format!(
            "must be at most {MAX_DOSSIER_TITLE_BYTES} bytes"
        )));
    }
    if title
        .chars()
        .any(|character| character.is_control() || character == '\u{feff}')
    {
        return Err(unusable("must not hold a control character"));
    }
    Ok(())
}

/// The one composition every title is written in: NFC, exactly what the
/// extraction sanitizer normalises a filename to.
fn canonical(title: &str) -> String {
    title.nfc().collect()
}

/// Turn a title rejection into the error the caller sees. The message says
/// which document and why, and never echoes the title itself.
fn title_error(index: usize, rejection: TitleRejection) -> Error {
    let reason = match rejection {
        TitleRejection::UnsafeTitle => {
            "is empty, too long, or holds a character that hides, reorders, or escapes"
        }
        TitleRejection::UnsafePath => "is not a single plain filename",
        TitleRejection::ReservedName => "uses a reserved device name",
    };
    Error::new(
        ErrorCode::UnsafeDocumentTitle,
        format!(
            "document {index} title {reason}; extraction would refuse it, so it is \
             refused here"
        ),
    )
}

/// Encode one document's payload, applying the transforms it asked for.
///
/// Returns the Base64 text and the transform chain, in the forward order the
/// profile declares (`zip? -> encrypt? -> base64`), which is the order the
/// specification fixes and the reader reverses.
fn encode(
    index: usize,
    document: &DocumentSpec,
    encryption: Option<&Encryption>,
    limits: &Limits,
) -> Result<(String, Vec<String>), Error> {
    if document.bytes.len() as u64 > limits.max_decoded_document_bytes {
        return Err(Error::new(
            ErrorCode::DecodedTooLarge,
            format!(
                "document {index} is larger than the {} byte limit",
                limits.max_decoded_document_bytes
            ),
        ));
    }
    let mut transforms = Vec::with_capacity(3);
    let mut payload = if document.compress {
        transforms.push("zip".to_owned());
        archive::compress(&document.title, &document.bytes, limits)?
    } else {
        document.bytes.clone()
    };
    // The encryption wraps whatever the ZIP step produced, so under `--zip`
    // the plaintext of the CMS message is the archive and the reader expands
    // it after decrypting.
    if let Some(encryption) = encryption.filter(|_| document.encrypt) {
        transforms.push("encrypt".to_owned());
        payload = encrypt::envelope(&payload, encryption)?;
    }
    transforms.push("base64".to_owned());
    let encoded = STANDARD.encode(&payload);
    if encoded.len() > limits.max_base64_chars {
        return Err(Error::new(
            ErrorCode::DecodedTooLarge,
            format!(
                "document {index} encodes to more than the {} Base64 character limit",
                limits.max_base64_chars
            ),
        ));
    }
    Ok((encoded, transforms))
}

/// Build a dossier from `spec`, within `limits`.
///
/// Every check happens before anything is rendered, so a refusal produces no
/// partial output. The returned bytes parse under the same limits.
pub fn build(spec: &DossierSpec, limits: &Limits) -> Result<BuiltDossier, Error> {
    check_dossier_title(&spec.title)?;
    if spec.documents.is_empty() {
        return Err(Error::new(
            ErrorCode::NoDocuments,
            "a dossier needs at least one document",
        ));
    }
    if spec.documents.len() > limits.max_documents {
        return Err(Error::new(
            ErrorCode::TooManyDocuments,
            format!("a dossier holds at most {} documents", limits.max_documents),
        ));
    }

    let mut total: u64 = 0;
    let mut documents = Vec::with_capacity(spec.documents.len());
    let mut payloads = Vec::with_capacity(spec.documents.len());
    for (index, document) in spec.documents.iter().enumerate() {
        let title = document.title.trim();
        check_title(title).map_err(|rejection| title_error(index, rejection))?;
        // One canonical composition, the same one the extraction sanitizer
        // writes a filename in, so the title in the dossier and the name the
        // payload comes back out under are the same string.
        let title = canonical(title);
        let mime_type = mime::mime_for(&title, document.media_type.as_deref())?;
        total = total.saturating_add(document.bytes.len() as u64);
        if total > limits.max_total_decoded_bytes {
            return Err(Error::new(
                ErrorCode::TotalSizeLimit,
                format!(
                    "the documents total more than the {} byte limit",
                    limits.max_total_decoded_bytes
                ),
            ));
        }
        let (payload, transforms) = encode(index, document, spec.encryption.as_ref(), limits)?;
        payloads.push(payload);
        documents.push(BuiltDocument {
            index,
            title,
            source_size: document.bytes.len() as u64,
            encrypted: transforms.iter().any(|transform| transform == "encrypt"),
            transforms,
            nested_dossier: is_nested_dossier(&mime_type),
            mime_type,
            object_ref: format!("obj{index}"),
        });
    }

    let profile_ids: Vec<String> = (0..documents.len())
        .map(|index| format!("profile{index}"))
        .collect();
    let rendered: Vec<render::RenderedDocument<'_>> = documents
        .iter()
        .enumerate()
        .map(|(index, document)| render::RenderedDocument {
            title: &document.title,
            created: &spec.created,
            mime_type: &document.mime_type,
            source_size: document.source_size,
            transforms: &document.transforms,
            object_id: &document.object_ref,
            profile_id: &profile_ids[index],
            payload: &payloads[index],
        })
        .collect();
    Ok(BuiltDossier {
        bytes: render::dossier(&canonical(spec.title.trim()), &spec.created, &rendered),
        documents,
    })
}

#[cfg(test)]
mod tests;
