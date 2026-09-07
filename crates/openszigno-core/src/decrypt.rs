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

use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo};
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Encode, Sequence};
use rsa::RsaPrivateKey;
use x509_cert::Certificate;
use x509_cert::spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use crate::{Error, ErrorCode, Limits};

/// RFC 5652 §3: the `ContentInfo` content types this module can be handed.
const ID_ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
/// RFC 5083 `id-ct-authEnvelopedData`, recognised only to say it is not supported.
const ID_AUTH_ENVELOPED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.23");

/// PKCS#1 `rsaEncryption`, which in a `keyEncryptionAlgorithm` means
/// RSAES-PKCS1-v1_5 key transport (RFC 8017 §7.2).
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// PKCS#1 `id-RSAES-OAEP` (RFC 8017 §7.1).
const RSAES_OAEP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
/// PKCS#1 `id-mgf1`.
const ID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
/// PKCS#1 `id-pSpecified`.
const ID_P_SPECIFIED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.9");

const ID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

const AES_128_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
const AES_192_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.22");
const AES_256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");
const DES_EDE3_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.3.7");

/// X.509 `id-ce-subjectKeyIdentifier`.
const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type TdesCbcDec = cbc::Decryptor<des::TdesEde3>;

/// `RSAES-OAEP-params` (RFC 8017 appendix A.2.1). Every field has a DEFAULT,
/// so an absent field means SHA-1 / MGF1-SHA-1 / empty label.
#[derive(Clone, Debug, Sequence)]
struct OaepParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    p_source: Option<AlgorithmIdentifierOwned>,
}

/// The recipient private key `extract` decrypts with, together with the
/// certificate that lets a `RecipientInfo` be recognised as naming it.
///
/// The key bytes never leave this type: it has no accessor for them, no
/// `Debug` that could print them, and every error raised while loading it is
/// a fixed string that quotes nothing.
pub struct RecipientKey {
    private: RsaPrivateKey,
    /// DER of the certificate's `issuer` field, for `issuerAndSerialNumber`.
    issuer_der: Vec<u8>,
    /// DER of the certificate's `serialNumber`, for `issuerAndSerialNumber`.
    serial_der: Vec<u8>,
    /// The certificate's `subjectKeyIdentifier` octets, when it has that
    /// extension. A recipient named by SKI cannot be matched without it.
    subject_key_identifier: Option<Vec<u8>>,
}

impl std::fmt::Debug for RecipientKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecipientKey")
            .finish_non_exhaustive()
    }
}

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

impl RecipientKey {
    /// Load a recipient key from PKCS#8 bytes and the certificate that
    /// identifies it.
    ///
    /// `key` is PKCS#8 in DER or PEM, plain (`PRIVATE KEY`) or passphrase
    /// protected (`ENCRYPTED PRIVATE KEY`). A PEM file may hold the
    /// certificate alongside the key, in which case `certificate` may be
    /// `None`. `passphrase` is only consulted for an encrypted key.
    ///
    /// Errors carry a stable code and a fixed message. They never quote the
    /// key, the passphrase, the certificate, or anything derived from them,
    /// and they do not distinguish "wrong passphrase" from "not a PKCS#8
    /// file", because both are answered the same way: check the inputs.
    pub fn load(
        key: &[u8],
        passphrase: Option<&[u8]>,
        certificate: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let private = load_private_key(key, passphrase)?;
        let certificate = match certificate {
            Some(bytes) => parse_certificate(bytes)?,
            None => certificate_in_pem(key)?.ok_or_else(|| {
                Error::new(
                    ErrorCode::DecryptionCertificateRequired,
                    "a decryption certificate is required: the key file carries no certificate, so the recipient it belongs to cannot be recognised",
                )
            })?,
        };
        Self::new(private, &certificate)
    }

    fn new(private: RsaPrivateKey, certificate: &Certificate) -> Result<Self, Error> {
        use rsa::pkcs8::DecodePublicKey as _;

        let spki = &certificate.tbs_certificate.subject_public_key_info;
        let certificate_key = rsa::RsaPublicKey::from_public_key_der(
            &spki.to_der().map_err(|_| invalid_certificate())?,
        )
        .map_err(|_| {
            Error::new(
                ErrorCode::InvalidDecryptionCertificate,
                "the decryption certificate does not carry an RSA public key",
            )
        })?;
        if rsa::RsaPublicKey::from(&private) != certificate_key {
            return Err(Error::new(
                ErrorCode::DecryptionKeyMismatch,
                "the decryption certificate does not belong to the decryption key",
            ));
        }
        Ok(Self {
            issuer_der: certificate
                .tbs_certificate
                .issuer
                .to_der()
                .map_err(|_| invalid_certificate())?,
            serial_der: certificate
                .tbs_certificate
                .serial_number
                .to_der()
                .map_err(|_| invalid_certificate())?,
            subject_key_identifier: subject_key_identifier(certificate)?,
            private,
        })
    }

    /// Whether a CMS `RecipientIdentifier` names this key's certificate.
    fn matches(&self, rid: &RecipientIdentifier) -> bool {
        match rid {
            RecipientIdentifier::IssuerAndSerialNumber(named) => {
                match (named.issuer.to_der(), named.serial_number.to_der()) {
                    (Ok(issuer), Ok(serial)) => {
                        issuer == self.issuer_der && serial == self.serial_der
                    }
                    _ => false,
                }
            }
            RecipientIdentifier::SubjectKeyIdentifier(identifier) => self
                .subject_key_identifier
                .as_deref()
                .is_some_and(|known| known == identifier.0.as_bytes()),
        }
    }
}

fn invalid_certificate() -> Error {
    Error::new(
        ErrorCode::InvalidDecryptionCertificate,
        "the decryption certificate is not a readable X.509 certificate",
    )
}

fn invalid_key() -> Error {
    Error::new(
        ErrorCode::InvalidDecryptionKey,
        "the decryption key could not be read: it must be an RSA private key in PKCS#8 DER or PEM form, and a passphrase must be supplied for an encrypted one",
    )
}

/// Read an RSA private key from PKCS#8 DER or PEM, decrypting it first when it
/// is a passphrase-protected `EncryptedPrivateKeyInfo`.
fn load_private_key(bytes: &[u8], passphrase: Option<&[u8]>) -> Result<RsaPrivateKey, Error> {
    use rsa::pkcs8::DecodePrivateKey as _;

    let der: Zeroizing<Vec<u8>> = match pem_blocks(bytes) {
        Some(blocks) => {
            let (label, body) = blocks
                .into_iter()
                .find(|(label, _)| label == "PRIVATE KEY" || label == "ENCRYPTED PRIVATE KEY")
                .ok_or_else(invalid_key)?;
            match label.as_str() {
                "ENCRYPTED PRIVATE KEY" => decrypt_pkcs8(&body, passphrase)?,
                _ => Zeroizing::new(body),
            }
        }
        None => match RsaPrivateKey::from_pkcs8_der(bytes) {
            Ok(key) => return Ok(key),
            Err(_) => decrypt_pkcs8(bytes, passphrase)?,
        },
    };
    RsaPrivateKey::from_pkcs8_der(&der).map_err(|_| invalid_key())
}

fn decrypt_pkcs8(der: &[u8], passphrase: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let passphrase = passphrase.ok_or_else(invalid_key)?;
    let encrypted = pkcs8::EncryptedPrivateKeyInfo::try_from(der).map_err(|_| invalid_key())?;
    let document = encrypted.decrypt(passphrase).map_err(|_| invalid_key())?;
    Ok(Zeroizing::new(document.as_bytes().to_vec()))
}

/// Every PEM block in `bytes` as `(label, DER body)`, or `None` when the input
/// is not PEM at all.
///
/// A malformed block inside otherwise-PEM input is skipped rather than
/// reported, so that a certificate bundle with a trailing comment still loads;
/// the caller fails on "no usable block" instead.
fn pem_blocks(bytes: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.contains("-----BEGIN ") {
        return None;
    }
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start..];
        let Some(header_end) = after.find("-----\n").or_else(|| after.find("-----\r\n")) else {
            break;
        };
        let label = after["-----BEGIN ".len()..header_end].to_owned();
        let footer = format!("-----END {label}-----");
        let Some(end) = after.find(&footer) else {
            break;
        };
        let block = &after[..end + footer.len()];
        if let Ok((_, body)) = pem_rfc7468::decode_vec(block.as_bytes()) {
            blocks.push((label, body));
        }
        rest = &after[end + footer.len()..];
    }
    Some(blocks)
}

/// The first `CERTIFICATE` block of a PEM key file, if there is one.
fn certificate_in_pem(bytes: &[u8]) -> Result<Option<Certificate>, Error> {
    let Some(blocks) = pem_blocks(bytes) else {
        return Ok(None);
    };
    match blocks.iter().find(|(label, _)| label == "CERTIFICATE") {
        Some((_, body)) => Ok(Some(
            Certificate::from_der(body).map_err(|_| invalid_certificate())?,
        )),
        None => Ok(None),
    }
}

fn parse_certificate(bytes: &[u8]) -> Result<Certificate, Error> {
    if let Some(blocks) = pem_blocks(bytes) {
        let (_, body) = blocks
            .into_iter()
            .find(|(label, _)| label == "CERTIFICATE")
            .ok_or_else(invalid_certificate)?;
        return Certificate::from_der(&body).map_err(|_| invalid_certificate());
    }
    Certificate::from_der(bytes).map_err(|_| invalid_certificate())
}

fn subject_key_identifier(certificate: &Certificate) -> Result<Option<Vec<u8>>, Error> {
    let Some(extensions) = certificate.tbs_certificate.extensions.as_ref() else {
        return Ok(None);
    };
    let Some(extension) = extensions
        .iter()
        .find(|extension| extension.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)
    else {
        return Ok(None);
    };
    let octets = OctetString::from_der(extension.extn_value.as_bytes())
        .map_err(|_| invalid_certificate())?;
    Ok(Some(octets.as_bytes().to_vec()))
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
    let content_info = ContentInfo::from_der(payload).map_err(|_| invalid_cms())?;
    if content_info.content_type == ID_AUTH_ENVELOPED_DATA {
        return Ok(CmsOutcome::UnsupportedAlgorithm(
            ID_AUTH_ENVELOPED_DATA.to_string(),
        ));
    }
    if content_info.content_type != ID_ENVELOPED_DATA {
        return Err(Error::new(
            ErrorCode::InvalidCms,
            "the encrypted payload is not a CMS EnvelopedData ContentInfo",
        ));
    }
    let enveloped: EnvelopedData = content_info
        .content
        .decode_as()
        .map_err(|_| invalid_cms())?;

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

    let cipher = match content_cipher(&enveloped.encrypted_content.content_enc_alg.oid) {
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

    let content_encryption_key = match unwrap_key(recipient, &key.private)? {
        Unwrapped::Key(cek) => cek,
        Unwrapped::UnsupportedAlgorithm(oid) => return Ok(CmsOutcome::UnsupportedAlgorithm(oid)),
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

    let plaintext = decrypt_content(
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

enum Unwrapped {
    Key(Zeroizing<Vec<u8>>),
    UnsupportedAlgorithm(String),
}

fn unwrap_key(
    recipient: &cms::enveloped_data::KeyTransRecipientInfo,
    private: &RsaPrivateKey,
) -> Result<Unwrapped, Error> {
    let algorithm = &recipient.key_enc_alg;
    let wrapped = recipient.enc_key.as_bytes();
    let key = if algorithm.oid == RSA_ENCRYPTION {
        private
            .decrypt(rsa::Pkcs1v15Encrypt, wrapped)
            .map_err(|_| decrypt_failed())?
    } else if algorithm.oid == RSAES_OAEP {
        match oaep_padding(algorithm)? {
            Some(padding) => private
                .decrypt(padding, wrapped)
                .map_err(|_| decrypt_failed())?,
            None => return Ok(Unwrapped::UnsupportedAlgorithm(RSAES_OAEP.to_string())),
        }
    } else {
        return Ok(Unwrapped::UnsupportedAlgorithm(algorithm.oid.to_string()));
    };
    Ok(Unwrapped::Key(Zeroizing::new(key)))
}

/// The OAEP padding an `id-RSAES-OAEP` algorithm identifier asks for, or
/// `None` when it asks for something outside the supported subset.
fn oaep_padding(algorithm: &AlgorithmIdentifierOwned) -> Result<Option<rsa::Oaep>, Error> {
    let parameters = match algorithm.parameters.as_ref() {
        Some(any) => any.decode_as::<OaepParams>().map_err(|_| invalid_cms())?,
        None => OaepParams {
            hash: None,
            mask_gen: None,
            p_source: None,
        },
    };
    let hash = parameters.hash.as_ref().map_or(ID_SHA1, |id| id.oid);
    // RFC 8017 requires MGF1 with the same hash. A different one is legal
    // ASN.1 but is not something this subset accepts, and silently ignoring
    // the mismatch would decrypt with the wrong mask.
    if let Some(mask_gen) = parameters.mask_gen.as_ref() {
        if mask_gen.oid != ID_MGF1 {
            return Ok(None);
        }
        let mgf_hash = mask_gen
            .parameters
            .as_ref()
            .and_then(|any| any.decode_as::<AlgorithmIdentifierOwned>().ok())
            .map_or(ID_SHA1, |id| id.oid);
        if mgf_hash != hash {
            return Ok(None);
        }
    } else if hash != ID_SHA1 {
        // The MGF1-SHA-1 default with a non-SHA-1 hash is a mismatch too.
        return Ok(None);
    }
    // Only the default empty label is supported; a labelled message is not
    // something the e-dossier format has any use for.
    if let Some(p_source) = parameters.p_source.as_ref() {
        if p_source.oid != ID_P_SPECIFIED {
            return Ok(None);
        }
        let empty = p_source
            .parameters
            .as_ref()
            .and_then(|any| any.decode_as::<OctetString>().ok())
            .is_some_and(|label| label.as_bytes().is_empty());
        if !empty {
            return Ok(None);
        }
    }
    Ok(if hash == ID_SHA1 {
        Some(rsa::Oaep::new::<sha1::Sha1>())
    } else if hash == ID_SHA256 {
        Some(rsa::Oaep::new::<sha2::Sha256>())
    } else if hash == ID_SHA384 {
        Some(rsa::Oaep::new::<sha2::Sha384>())
    } else if hash == ID_SHA512 {
        Some(rsa::Oaep::new::<sha2::Sha512>())
    } else {
        None
    })
}

#[derive(Clone, Copy)]
enum CipherKind {
    Aes128,
    Aes192,
    Aes256,
    TripleDes,
}

struct ContentCipher {
    kind: CipherKind,
    key_bytes: usize,
    block_bytes: usize,
    legacy: bool,
}

fn content_cipher(oid: &ObjectIdentifier) -> Option<ContentCipher> {
    let cipher = if *oid == AES_128_CBC {
        ContentCipher {
            kind: CipherKind::Aes128,
            key_bytes: 16,
            block_bytes: 16,
            legacy: false,
        }
    } else if *oid == AES_192_CBC {
        ContentCipher {
            kind: CipherKind::Aes192,
            key_bytes: 24,
            block_bytes: 16,
            legacy: false,
        }
    } else if *oid == AES_256_CBC {
        ContentCipher {
            kind: CipherKind::Aes256,
            key_bytes: 32,
            block_bytes: 16,
            legacy: false,
        }
    } else if *oid == DES_EDE3_CBC {
        ContentCipher {
            kind: CipherKind::TripleDes,
            key_bytes: 24,
            block_bytes: 8,
            legacy: true,
        }
    } else {
        return None;
    };
    Some(cipher)
}

fn decrypt_content(
    kind: CipherKind,
    key: &[u8],
    initialisation_vector: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    // An empty or non-block-aligned ciphertext cannot be CBC output; the
    // decryptors below reject it too, but saying so here keeps the failure a
    // structural one rather than an unexplained "decryption failed".
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(initialisation_vector.len()) {
        return Err(Error::new(
            ErrorCode::InvalidCms,
            "the encrypted content length is not a whole number of cipher blocks",
        ));
    }
    let iv = initialisation_vector;
    let plaintext = match kind {
        CipherKind::Aes128 => Aes128CbcDec::new_from_slices(key, iv)
            .map_err(|_| decrypt_failed())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext),
        CipherKind::Aes192 => Aes192CbcDec::new_from_slices(key, iv)
            .map_err(|_| decrypt_failed())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext),
        CipherKind::Aes256 => Aes256CbcDec::new_from_slices(key, iv)
            .map_err(|_| decrypt_failed())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext),
        CipherKind::TripleDes => TdesCbcDec::new_from_slices(key, iv)
            .map_err(|_| decrypt_failed())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext),
    };
    plaintext.map_err(|_| decrypt_failed())
}

#[cfg(test)]
mod tests {
    //! Unit tests for the algorithm and framing decisions.
    //!
    //! The round trips live in `tests/decryption.rs`, which can build whole
    //! synthetic messages. These cover the branches that a well-formed message
    //! from a cooperating sender never reaches: algorithm identifiers outside
    //! the subset, and framing a real encryptor would not produce.

    use der::asn1::Any;

    use super::*;

    /// PEM armour, assembled at run time.
    ///
    /// A finished `BEGIN ... PRIVATE KEY` line never appears as a literal in
    /// this repository. A secret scanner cannot tell a real key block from a
    /// test string that only looks like one, and this project does not
    /// allowlist scanner rules, so the only safe amount of key-shaped text in
    /// the tree is none. See `SECURITY.md`.
    fn armour(label: &str, body: &str) -> String {
        let begin = format!("-----{}{label}-----", "BEGIN ");
        match body {
            // A header with no terminator at all.
            "" => begin,
            _ => format!("{begin}\n{body}\n-----{}{label}-----\n", "END "),
        }
    }

    /// The same, with the closing line left off.
    fn unterminated(label: &str, body: &str) -> String {
        format!("{}\n{body}\n", armour(label, ""))
    }

    fn algorithm(oid: ObjectIdentifier, parameters: Option<Any>) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned { oid, parameters }
    }

    fn nested(value: &AlgorithmIdentifierOwned) -> Any {
        Any::from_der(&value.to_der().expect("DER")).expect("the identifier is DER")
    }

    fn oaep(
        hash: Option<ObjectIdentifier>,
        mask_gen: Option<AlgorithmIdentifierOwned>,
        p_source: Option<AlgorithmIdentifierOwned>,
    ) -> AlgorithmIdentifierOwned {
        let parameters = OaepParams {
            hash: hash.map(|oid| algorithm(oid, Some(Any::null()))),
            mask_gen,
            p_source,
        };
        algorithm(
            RSAES_OAEP,
            Some(Any::from_der(&parameters.to_der().expect("DER")).expect("params are DER")),
        )
    }

    fn mgf1(hash: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        algorithm(ID_MGF1, Some(nested(&algorithm(hash, Some(Any::null())))))
    }

    #[test]
    fn absent_oaep_parameters_mean_the_sha1_defaults() {
        let padding = oaep_padding(&algorithm(RSAES_OAEP, None)).expect("the defaults parse");
        assert!(padding.is_some(), "SHA-1 with MGF1-SHA-1 is supported");
    }

    #[test]
    fn every_supported_oaep_hash_is_accepted_with_its_matching_mgf1() {
        for hash in [ID_SHA1, ID_SHA256, ID_SHA384, ID_SHA512] {
            let algorithm = oaep(Some(hash), Some(mgf1(hash)), None);
            assert!(
                oaep_padding(&algorithm)
                    .expect("the parameters parse")
                    .is_some(),
                "{hash} must be supported"
            );
        }
    }

    #[test]
    fn oaep_parameters_outside_the_subset_are_unsupported_rather_than_guessed_at() {
        // MD5, which is not in the subset at all.
        let unknown_hash = ObjectIdentifier::new_unwrap("1.2.840.113549.2.5");
        let empty_label = algorithm(
            ID_P_SPECIFIED,
            Some(
                Any::from_der(
                    &OctetString::new(Vec::new())
                        .expect("empty")
                        .to_der()
                        .expect("DER"),
                )
                .expect("the label is DER"),
            ),
        );
        let labelled = algorithm(
            ID_P_SPECIFIED,
            Some(
                Any::from_der(
                    &OctetString::new(b"label".to_vec())
                        .expect("a label")
                        .to_der()
                        .expect("DER"),
                )
                .expect("the label is DER"),
            ),
        );
        for (case, identifier) in [
            (
                "a mask generation function that is not MGF1",
                oaep(
                    Some(ID_SHA256),
                    Some(algorithm(ID_SHA256, Some(Any::null()))),
                    None,
                ),
            ),
            (
                "an MGF1 hash that differs from the OAEP hash",
                oaep(Some(ID_SHA256), Some(mgf1(ID_SHA1)), None),
            ),
            (
                "a non-SHA-1 hash relying on the MGF1-SHA-1 default",
                oaep(Some(ID_SHA256), None, None),
            ),
            (
                "a label source that is not pSpecified",
                oaep(Some(ID_SHA1), Some(mgf1(ID_SHA1)), Some(mgf1(ID_SHA1))),
            ),
            (
                "a non-empty label",
                oaep(Some(ID_SHA1), Some(mgf1(ID_SHA1)), Some(labelled)),
            ),
            (
                "a hash outside the subset",
                oaep(Some(unknown_hash), Some(mgf1(unknown_hash)), None),
            ),
        ] {
            assert!(
                oaep_padding(&identifier)
                    .expect("the parameters parse")
                    .is_none(),
                "{case} must be unsupported"
            );
        }
        // The default empty label is accepted when it is spelled out.
        assert!(
            oaep_padding(&oaep(Some(ID_SHA1), Some(mgf1(ID_SHA1)), Some(empty_label)))
                .expect("the parameters parse")
                .is_some()
        );
    }

    #[test]
    fn malformed_oaep_parameters_are_malformed_cms() {
        let identifier = algorithm(RSAES_OAEP, Some(Any::null()));
        assert_eq!(
            oaep_padding(&identifier)
                .expect_err("null parameters are not RSAES-OAEP-params")
                .code(),
            ErrorCode::InvalidCms
        );
    }

    #[test]
    fn the_content_cipher_table_matches_the_documented_subset() {
        for (oid, key_bytes, block_bytes, legacy) in [
            (AES_128_CBC, 16, 16, false),
            (AES_192_CBC, 24, 16, false),
            (AES_256_CBC, 32, 16, false),
            (DES_EDE3_CBC, 24, 8, true),
        ] {
            let cipher = content_cipher(&oid).expect("the cipher is supported");
            assert_eq!(cipher.key_bytes, key_bytes);
            assert_eq!(cipher.block_bytes, block_bytes);
            assert_eq!(cipher.legacy, legacy);
        }
        // RC2-CBC: a real CMS cipher this build does not implement.
        assert!(
            content_cipher(&ObjectIdentifier::new_unwrap("1.2.840.113549.3.2")).is_none(),
            "an unlisted cipher is not silently accepted"
        );
    }

    #[test]
    fn a_ciphertext_that_is_not_whole_blocks_is_malformed_cms() {
        for ciphertext in [b"".to_vec(), b"short".to_vec(), vec![0u8; 17]] {
            let error = decrypt_content(CipherKind::Aes128, &[0u8; 16], &[0u8; 16], &ciphertext)
                .expect_err("a partial block cannot be CBC output");
            assert_eq!(error.code(), ErrorCode::InvalidCms);
        }
    }

    #[test]
    fn every_supported_cipher_kind_rejects_garbage_as_a_plain_failure() {
        // The padding of a random block is almost never valid, and when it is,
        // the answer is still a plaintext rather than a leak of which step
        // went wrong. Either way the caller learns nothing beyond the fixed
        // message.
        for (kind, key, block) in [
            (CipherKind::Aes128, 16, 16),
            (CipherKind::Aes192, 24, 16),
            (CipherKind::Aes256, 32, 16),
            (CipherKind::TripleDes, 24, 8),
        ] {
            let outcome =
                decrypt_content(kind, &vec![0u8; key], &vec![0u8; block], &vec![0xff; block]);
            if let Err(error) = outcome {
                assert_eq!(error.code(), ErrorCode::DecryptFailed);
                assert_eq!(error.message(), "decryption failed");
            }
        }
    }

    #[test]
    fn a_key_or_iv_of_the_wrong_length_is_a_plain_failure() {
        let error = decrypt_content(CipherKind::Aes128, &[0u8; 8], &[0u8; 16], &[0u8; 16])
            .expect_err("a short key cannot build a cipher");
        assert_eq!(error.code(), ErrorCode::DecryptFailed);
    }

    #[test]
    fn input_that_is_not_pem_at_all_is_recognised_as_der() {
        assert!(pem_blocks(b"\x30\x82\x01\x00").is_none());
        assert!(pem_blocks(b"plain text with no armour").is_none());
    }

    /// The label every armour test uses, spelled apart from its delimiters.
    const PRIVATE_KEY: &str = "PRIVATE KEY";
    const CERTIFICATE: &str = "CERTIFICATE";

    #[test]
    fn a_truncated_or_unreadable_pem_block_is_skipped_rather_than_reported() {
        // A header with no terminator, an unterminated block, and a block
        // whose body is not base64: each leaves the file with no usable block,
        // which the caller turns into one "unreadable key" answer.
        for input in [
            armour(PRIVATE_KEY, ""),
            unterminated(PRIVATE_KEY, "AAAA"),
            armour(PRIVATE_KEY, "!!!!"),
        ] {
            let blocks = pem_blocks(input.as_bytes()).expect("the input looks like PEM");
            assert!(blocks.is_empty(), "{input:?} yields no usable block");
        }
        assert_eq!(
            load_private_key(armour(PRIVATE_KEY, "").as_bytes(), None)
                .expect_err("no block means no key")
                .code(),
            ErrorCode::InvalidDecryptionKey
        );
    }

    #[test]
    fn a_certificate_that_is_neither_pem_nor_der_is_reported_as_such() {
        for input in [
            b"not a certificate".to_vec(),
            // PEM that holds no certificate block at all.
            armour(PRIVATE_KEY, "").into_bytes(),
        ] {
            assert_eq!(
                parse_certificate(&input)
                    .expect_err("this is not a certificate")
                    .code(),
                ErrorCode::InvalidDecryptionCertificate
            );
        }
        assert!(
            certificate_in_pem(b"\x30\x00")
                .expect("DER input carries no PEM certificate")
                .is_none()
        );
        assert_eq!(
            certificate_in_pem(armour(CERTIFICATE, "AAAA").as_bytes())
                .expect_err("the block is not a certificate")
                .code(),
            ErrorCode::InvalidDecryptionCertificate
        );
    }

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
        let key = unusable_key();
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

    /// A key that is never asked to decrypt anything, for the framing tests
    /// that fail before any recipient is looked at.
    fn unusable_key() -> RecipientKey {
        // A textbook-sized key: it is never asked to decrypt anything here,
        // and embedding a full-size one would only slow the suite.
        RecipientKey {
            private: rsa::RsaPrivateKey::from_components(
                rsa::BigUint::from(3233u32),
                rsa::BigUint::from(17u32),
                rsa::BigUint::from(413u32),
                vec![rsa::BigUint::from(61u32), rsa::BigUint::from(53u32)],
            )
            .expect("the textbook RSA key builds"),
            issuer_der: Vec::new(),
            serial_der: Vec::new(),
            subject_key_identifier: None,
        }
    }

    #[test]
    fn the_key_type_never_prints_its_key() {
        let rendered = format!("{:?}", unusable_key());
        assert_eq!(rendered, "RecipientKey { .. }");
    }
}
