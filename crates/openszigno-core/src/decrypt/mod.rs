//! Decryption of the e-dossier `encrypt` transform.
//!
//! The e-dossier specification says only that `encrypt` is "S/MIME
//! encryption" and that `es:RecipientCertificateList` may name the
//! certificates whose private keys can undo it. It fixes no algorithms and no
//! recipient-identifier form. Microsec's own `eszigno3` reference CLI is more
//! concrete: its `cm_decrypt` command is documented as "RFC5652 szerinti CMS
//! titkosítás feloldása" — undoing CMS encryption per RFC 5652 — and its
//! `export_recipient_infos` command exports the recipients' certificates *and
//! their encrypted keys*, which is the CMS `RecipientInfos` structure. This
//! module therefore reads the Base64-decoded payload as a DER
//! `ContentInfo` carrying `id-envelopedData` (RFC 5652 §6).
//!
//! What is supported is deliberately a small subset, listed in
//! `docs/architecture.md`:
//!
//! - `KeyTransRecipientInfo` only, with the recipient named either by
//!   `issuerAndSerialNumber` or by `subjectKeyIdentifier`;
//! - key transport with RSAES-PKCS1-v1_5 or RSAES-OAEP (MGF1, SHA-1/256/384/512);
//! - content encryption with AES-128/192/256-CBC, and DES-EDE3-CBC only when
//!   the caller opts in, because it is weak and is merely what the reference
//!   implementation defaulted to.
//!
//! Nothing here establishes authenticity. Decrypting a document says a key
//! could unwrap it, not that anybody signed it.
//!
//! The module is split by concern: [`cms`] parses and validates the CMS
//! `ContentInfo` / `EnvelopedData` / `RecipientInfo` structure and unwraps the
//! content-encryption key; [`ciphers`] identifies and runs the content
//! cipher; [`keys`] loads the recipient's private key and matches it against
//! a `RecipientIdentifier`. This module ties the three together and holds the
//! public entry points.

mod ciphers;
mod cms;
mod keys;

use ::cms::enveloped_data::RecipientInfo;
use der::asn1::OctetString;

pub use keys::RecipientKey;

use crate::{Error, ErrorCode, Limits};

/// How `decode_document_with` may treat an encrypted document.
///
/// The default decrypts nothing: an encrypted document stays skipped unless
/// the caller supplies a key.
#[derive(Clone, Copy, Debug, Default)]
pub struct DecryptOptions<'a> {
    /// The recipient key, or `None` to keep encrypted documents skipped.
    pub key: Option<&'a RecipientKey>,
    /// Accept DES-EDE3-CBC content encryption. Off by default: 3DES has a
    /// 64-bit block and an effective strength well below its key length.
    pub allow_legacy_ciphers: bool,
}

/// What one CMS payload turned into.
///
/// Everything except `Plaintext` is a reason to skip the document rather than
/// to fail the run: another recipient's document, or one encrypted with an
/// algorithm outside the supported subset, is not a broken dossier.
pub(crate) enum CmsOutcome {
    Plaintext(Vec<u8>),
    NoMatchingRecipient,
    UnsupportedAlgorithm(String),
    LegacyCipher(String),
}

impl std::fmt::Debug for CmsOutcome {
    /// Deliberately hand-written: a derived `Debug` would print the decrypted
    /// bytes, and a plaintext must never reach a diagnostic by accident.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext(bytes) => write!(formatter, "Plaintext({} bytes)", bytes.len()),
            Self::NoMatchingRecipient => formatter.write_str("NoMatchingRecipient"),
            Self::UnsupportedAlgorithm(oid) => write!(formatter, "UnsupportedAlgorithm({oid})"),
            Self::LegacyCipher(oid) => write!(formatter, "LegacyCipher({oid})"),
        }
    }
}

/// Undo one `encrypt` transform.
///
/// `payload` is the Base64-decoded document: a DER `ContentInfo`. The result
/// is the enveloped content, bounded by `max_decoded_document_bytes` both
/// before the plaintext buffer is allocated (using the ciphertext length,
/// which the plaintext can never exceed) and again once it exists.
pub(crate) fn decrypt_cms(
    payload: &[u8],
    key: &RecipientKey,
    allow_legacy_ciphers: bool,
    limits: &Limits,
) -> Result<CmsOutcome, Error> {
    let enveloped = match cms::parse_content_info(payload)? {
        Err(outcome) => return Ok(outcome),
        Ok(enveloped) => enveloped,
    };

    let Some(recipient) = enveloped
        .recip_infos
        .0
        .iter()
        .filter_map(|info| match info {
            RecipientInfo::Ktri(ktri) => Some(ktri),
            _ => None,
        })
        .find(|ktri| key.matches(&ktri.rid))
    else {
        return Ok(CmsOutcome::NoMatchingRecipient);
    };

    let cipher = match ciphers::content_cipher(&enveloped.encrypted_content.content_enc_alg.oid) {
        Some(cipher) => cipher,
        None => {
            return Ok(CmsOutcome::UnsupportedAlgorithm(
                enveloped.encrypted_content.content_enc_alg.oid.to_string(),
            ));
        }
    };
    if cipher.legacy && !allow_legacy_ciphers {
        return Ok(CmsOutcome::LegacyCipher(
            enveloped.encrypted_content.content_enc_alg.oid.to_string(),
        ));
    }

    let content_encryption_key = match cms::unwrap_key(recipient, &key.private)? {
        cms::Unwrapped::Key(cek) => cek,
        cms::Unwrapped::UnsupportedAlgorithm(oid) => {
            return Ok(CmsOutcome::UnsupportedAlgorithm(oid));
        }
    };
    if content_encryption_key.len() != cipher.key_bytes {
        // A CEK of the wrong length is what a wrong key usually produces, so
        // it is answered exactly like a failed unwrap.
        return Err(decrypt_failed());
    }

    let initialisation_vector = enveloped
        .encrypted_content
        .content_enc_alg
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<OctetString>().ok())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidCms,
                "the content encryption algorithm carries no initialisation vector",
            )
        })?;
    if initialisation_vector.as_bytes().len() != cipher.block_bytes {
        return Err(Error::new(
            ErrorCode::InvalidCms,
            "the content encryption initialisation vector has the wrong length",
        ));
    }

    let ciphertext = enveloped
        .encrypted_content
        .encrypted_content
        .as_ref()
        .ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidCms,
                "the CMS EnvelopedData carries no encrypted content; detached content is not supported",
            )
        })?;
    // The plaintext is never longer than the ciphertext, so this bounds the
    // buffer before it is allocated.
    if ciphertext.as_bytes().len() as u64 > limits.max_decoded_document_bytes {
        return Err(Error::new(
            ErrorCode::DecodedTooLarge,
            "encrypted document exceeds the decoded-size limit",
        ));
    }

    let plaintext = ciphers::decrypt_content(
        cipher.kind,
        &content_encryption_key,
        initialisation_vector.as_bytes(),
        ciphertext.as_bytes(),
    )?;
    if plaintext.len() as u64 > limits.max_decoded_document_bytes {
        return Err(Error::new(
            ErrorCode::DecodedTooLarge,
            "decrypted document exceeds the decoded-size limit",
        ));
    }
    Ok(CmsOutcome::Plaintext(plaintext))
}

fn invalid_cms() -> Error {
    Error::new(
        ErrorCode::InvalidCms,
        "the encrypted payload is not well-formed CMS",
    )
}

/// The single message every decryption failure gets.
///
/// It deliberately does not say whether the key unwrap, the CEK length, or the
/// padding was what failed: telling those apart is exactly the distinction a
/// padding oracle needs.
fn decrypt_failed() -> Error {
    Error::new(ErrorCode::DecryptFailed, "decryption failed")
}

#[cfg(test)]
mod tests {
    //! Unit tests for the `decrypt_cms` orchestration: which `ContentInfo`
    //! shapes are recognised, named as unsupported, or rejected outright.
    //!
    //! The round trips live in `tests/decryption.rs`, which can build whole
    //! synthetic messages.

    use ::cms::content_info::ContentInfo;
    use const_oid::ObjectIdentifier;
    use der::Encode;

    use super::cms::{ID_AUTH_ENVELOPED_DATA, ID_ENVELOPED_DATA};
    use super::*;

    #[test]
    fn a_content_info_that_is_not_enveloped_data_is_named_or_refused() {
        fn content_info(content_type: ObjectIdentifier) -> Vec<u8> {
            ContentInfo {
                content_type,
                content: der::asn1::Any::null(),
            }
            .to_der()
            .expect("ContentInfo encodes")
        }
        let key = RecipientKey::unusable_for_tests();
        let limits = Limits::default();

        // RFC 5083 AuthEnvelopedData is recognised, and skipped by name.
        let outcome = decrypt_cms(&content_info(ID_AUTH_ENVELOPED_DATA), &key, false, &limits)
            .expect("a recognised container is not an error");
        match outcome {
            CmsOutcome::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid, ID_AUTH_ENVELOPED_DATA.to_string());
            }
            _ => panic!("AuthEnvelopedData must be reported as unsupported"),
        }

        // id-data, or anything else, is not an encrypted document at all.
        let error = decrypt_cms(
            &content_info(ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")),
            &key,
            false,
            &limits,
        )
        .expect_err("a non-enveloped container is malformed");
        assert_eq!(error.code(), ErrorCode::InvalidCms);

        // And neither is a payload that is not DER.
        assert_eq!(
            decrypt_cms(b"not DER", &key, false, &limits)
                .expect_err("garbage is malformed")
                .code(),
            ErrorCode::InvalidCms
        );
        // Nor a ContentInfo whose content is not an EnvelopedData.
        assert_eq!(
            decrypt_cms(&content_info(ID_ENVELOPED_DATA), &key, false, &limits)
                .expect_err("a null EnvelopedData is malformed")
                .code(),
            ErrorCode::InvalidCms
        );
    }
}
