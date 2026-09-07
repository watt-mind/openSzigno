use std::io::{Cursor, Read};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use zip::ZipArchive;

use crate::decrypt::{CmsOutcome, DecryptOptions, decrypt_cms};
use crate::{Document, Error, ErrorCode, Limits};

/// Why a document that parsed could not be turned back into its source bytes.
///
/// Every variant is a reason to skip one document, never to fail a run: a
/// dossier addressed to somebody else is a perfectly valid dossier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReason {
    /// The document is encrypted and no decryption key was supplied.
    Encrypted,
    /// The transform chain is not one this crate reverses.
    TransformChain,
    /// The document is encrypted, a key was supplied, and no `RecipientInfo`
    /// names that key's certificate.
    NoMatchingRecipient,
    /// The CMS message uses a key-transport or content-encryption algorithm
    /// outside the supported subset. `oid` names it.
    UnsupportedCipher { oid: String },
    /// The content is encrypted with DES-EDE3-CBC and legacy ciphers were not
    /// allowed. `oid` names it.
    LegacyCipher { oid: String },
}

#[derive(Clone, Debug)]
pub struct DecodedDocument {
    pub bytes: Vec<u8>,
    /// Whether an `encrypt` transform was reversed to produce `bytes`.
    ///
    /// This says a supplied key unwrapped the content encryption key, and
    /// nothing at all about who produced the document or whether it is signed.
    pub decrypted: bool,
}

#[derive(Clone, Debug)]
pub enum DecodeOutcome {
    Decoded(DecodedDocument),
    Unsupported(UnsupportedReason),
}

/// Decode one document without any decryption key, the behaviour
/// [`Dossier::decode_document`](crate::Dossier::decode_document) exposes.
pub(crate) fn decode_document(
    document: &Document,
    limits: &Limits,
) -> Result<DecodeOutcome, Error> {
    decode_document_with_options(document, limits, &DecryptOptions::default())
}

fn decode_document_with_options(
    document: &Document,
    limits: &Limits,
    decrypt: &DecryptOptions<'_>,
) -> Result<DecodeOutcome, Error> {
    // The specification fixes the forward order as `zip? -> encrypt? ->
    // base64`, so reversing it is base64, then decryption, then expansion.
    let (encrypted, compressed) = match document.transforms.as_slice() {
        [base64] if base64 == "base64" => (false, false),
        [zip, base64] if zip == "zip" && base64 == "base64" => (false, true),
        [encrypt, base64] if encrypt == "encrypt" && base64 == "base64" => (true, false),
        [zip, encrypt, base64] if zip == "zip" && encrypt == "encrypt" && base64 == "base64" => {
            (true, true)
        }
        _ => {
            return Ok(DecodeOutcome::Unsupported(
                UnsupportedReason::TransformChain,
            ));
        }
    };

    let mut decoded = decode_base64(&document.payload, limits)?;
    if encrypted {
        let Some(key) = decrypt.key else {
            return Ok(DecodeOutcome::Unsupported(UnsupportedReason::Encrypted));
        };
        decoded = match decrypt_cms(&decoded, key, decrypt.allow_legacy_ciphers, limits)? {
            CmsOutcome::Plaintext(plaintext) => plaintext,
            CmsOutcome::NoMatchingRecipient => {
                return Ok(DecodeOutcome::Unsupported(
                    UnsupportedReason::NoMatchingRecipient,
                ));
            }
            CmsOutcome::UnsupportedAlgorithm(oid) => {
                return Ok(DecodeOutcome::Unsupported(
                    UnsupportedReason::UnsupportedCipher { oid },
                ));
            }
            CmsOutcome::LegacyCipher(oid) => {
                return Ok(DecodeOutcome::Unsupported(
                    UnsupportedReason::LegacyCipher { oid },
                ));
            }
        };
    }
    if compressed {
        decoded = decode_zip(&decoded, limits)?;
    }

    // Without a declared size there is nothing to compare against; the
    // omission is reported as a structural warning when the dossier is parsed.
    if document
        .source_size
        .is_some_and(|declared| decoded.len() as u64 != declared)
    {
        return Err(Error::new(
            ErrorCode::SourceSizeMismatch,
            format!(
                "document {} decoded size does not match its declared source size",
                document.index
            ),
        ));
    }
    Ok(DecodeOutcome::Decoded(DecodedDocument {
        bytes: decoded,
        decrypted: encrypted,
    }))
}

/// Decode one document of `dossier`, decrypting it when the options allow.
///
/// This is [`Dossier::decode_document`](crate::Dossier::decode_document) with
/// a decryption policy. With [`DecryptOptions::default`] the two behave
/// identically: an encrypted document is reported as
/// [`UnsupportedReason::Encrypted`] and skipped.
pub fn decode_document_with(
    dossier: &crate::Dossier,
    index: usize,
    limits: &Limits,
    decrypt: &DecryptOptions<'_>,
) -> Result<DecodeOutcome, Error> {
    decode_document_with_options(
        dossier.documents.get(index).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidAttribute,
                "document index is out of range",
            )
        })?,
        limits,
        decrypt,
    )
}

fn decode_base64(payload: &str, limits: &Limits) -> Result<Vec<u8>, Error> {
    let compact: Vec<u8> = payload
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if compact.len() > limits.max_base64_chars {
        return Err(Error::new(
            ErrorCode::DecodedTooLarge,
            "Base64 payload exceeds the encoded-size limit",
        ));
    }
    let estimated = compact.len().div_ceil(4).saturating_mul(3) as u64;
    if estimated > limits.max_decoded_document_bytes {
        return Err(Error::new(
            ErrorCode::DecodedTooLarge,
            "Base64 payload exceeds the decoded-size limit",
        ));
    }
    let decoded = STANDARD.decode(compact).map_err(|_| {
        Error::new(
            ErrorCode::InvalidBase64,
            "document payload is not valid canonical Base64",
        )
    })?;
    if decoded.len() as u64 > limits.max_decoded_document_bytes {
        return Err(Error::new(
            ErrorCode::DecodedTooLarge,
            "decoded document exceeds the size limit",
        ));
    }
    Ok(decoded)
}

fn decode_zip(archive_bytes: &[u8], limits: &Limits) -> Result<Vec<u8>, Error> {
    let reader = Cursor::new(archive_bytes);
    let mut archive = ZipArchive::new(reader)
        .map_err(|_| Error::new(ErrorCode::InvalidZip, "payload is not a valid ZIP archive"))?;
    if archive.len() != 1 || archive.len() > limits.max_zip_members {
        return Err(Error::new(
            ErrorCode::ZipMemberLimit,
            "compressed document ZIP must contain exactly one member",
        ));
    }

    let member = archive.by_index(0).map_err(|error| match error {
        zip::result::ZipError::UnsupportedArchive(_)
        | zip::result::ZipError::CompressionMethodNotSupported(_) => Error::new(
            ErrorCode::UnsupportedZipMember,
            "ZIP member uses encryption or an unsupported compression method",
        ),
        _ => Error::new(ErrorCode::InvalidZip, "cannot read ZIP member"),
    })?;
    let enclosed = member
        .enclosed_name()
        .ok_or_else(|| Error::new(ErrorCode::UnsafeZipMember, "ZIP member has an unsafe path"))?;
    if member.is_dir()
        || enclosed.components().count() != 1
        || member
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
    {
        return Err(Error::new(
            ErrorCode::UnsafeZipMember,
            "ZIP member must be one regular file with a basename",
        ));
    }

    let expanded_size = member.size();
    if expanded_size > limits.max_zip_expanded_bytes
        || expanded_size > limits.max_decoded_document_bytes
    {
        return Err(Error::new(
            ErrorCode::ZipSizeLimit,
            "ZIP member exceeds the expanded-size limit",
        ));
    }
    // Header sizes are attacker-controlled. This check is only a cheap
    // pre-filter; the authoritative ratio check below uses the actual
    // decoded length against the actual archive length.
    let compressed_size = member.compressed_size().min(archive_bytes.len() as u64);
    if exceeds_ratio(expanded_size, compressed_size, limits) {
        return Err(Error::new(
            ErrorCode::ZipRatioLimit,
            "ZIP member exceeds the compression-ratio limit",
        ));
    }

    let mut decoded = Vec::with_capacity(expanded_size.min(usize::MAX as u64) as usize);
    let read_limit = limits
        .max_zip_expanded_bytes
        .min(limits.max_decoded_document_bytes)
        .saturating_add(1);
    member
        .take(read_limit)
        .read_to_end(&mut decoded)
        .map_err(|_| Error::new(ErrorCode::InvalidZip, "cannot expand ZIP member"))?;
    if decoded.len() as u64 >= read_limit {
        return Err(Error::new(
            ErrorCode::ZipSizeLimit,
            "ZIP member exceeded the expanded-size limit while reading",
        ));
    }
    if exceeds_ratio(decoded.len() as u64, compressed_size, limits) {
        return Err(Error::new(
            ErrorCode::ZipRatioLimit,
            "ZIP member exceeded the compression-ratio limit while reading",
        ));
    }
    Ok(decoded)
}

fn exceeds_ratio(expanded: u64, compressed: u64, limits: &Limits) -> bool {
    expanded > 0
        && (compressed == 0
            || expanded > compressed.saturating_mul(limits.max_zip_compression_ratio))
}
