//! The `encrypt` transform: building a CMS `EnvelopedData` for one or more
//! recipient certificates.
//!
//! This is the exact inverse of what `openszigno-core`'s `decrypt` module
//! reads, and it deliberately writes only the middle of that module's
//! supported subset:
//!
//! | Layer | What is written |
//! | --- | --- |
//! | Container | `ContentInfo` with `id-envelopedData` (RFC 5652 §6), bare DER, no MIME wrapper. |
//! | Recipient | One `KeyTransRecipientInfo` per certificate, named by `issuerAndSerialNumber`. |
//! | Key transport | RSAES-OAEP with SHA-256 and MGF1-SHA-256, or RSAES-PKCS1-v1_5 under [`KeyTransport::Pkcs1v15`]. |
//! | Content encryption | AES-256-CBC, with a fresh content-encryption key and initialisation vector per document. |
//!
//! DES-EDE3-CBC is never written. The reader accepts it behind
//! `--allow-legacy-ciphers` because real dossiers carry it, which is a reason
//! to read it and not a reason to produce more of it.
//!
//! **This is the one thing in this crate that is not deterministic.** The
//! content-encryption key, the initialisation vector, and the key-transport
//! padding all come from [`rand_core::OsRng`], so two runs over the same
//! inputs produce different bytes. That is a property of encryption, not a
//! defect: a fixed key or IV would make every document this tool wrote
//! decryptable by anyone who read the source. Without `--encrypt-for` the
//! crate consults no random source at all and the determinism guarantee is
//! unchanged.
//!
//! Nothing here authenticates anything. Encrypting a document says who can
//! read it, not who wrote it, and a dossier this crate builds is still
//! unsigned.

mod recipient;

use cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::enveloped_data::{
    EncryptedContentInfo, EnvelopedData, KeyTransRecipientInfo, RecipientInfo, RecipientInfos,
};
use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode, Sequence};
use rand_core::{OsRng, RngCore as _};
use x509_cert::spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use crate::error::{Error, ErrorCode};

pub use recipient::Recipient;

/// RFC 5652 §4 `id-data`, the content type of the enveloped plaintext.
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// RFC 5652 §6 `id-envelopedData`.
const ID_ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
/// NIST `id-aes256-CBC`.
const AES_256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");
/// PKCS#1 `rsaEncryption`, which in a `keyEncryptionAlgorithm` means
/// RSAES-PKCS1-v1_5 key transport (RFC 8017 §7.2).
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// PKCS#1 `id-RSAES-OAEP` (RFC 8017 §7.1).
const RSAES_OAEP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
/// PKCS#1 `id-mgf1`.
const ID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// AES-256 key length, and the AES block length, in bytes.
const CONTENT_KEY_BYTES: usize = 32;
const BLOCK_BYTES: usize = 16;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

/// How the content-encryption key is wrapped for each recipient.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum KeyTransport {
    /// RSAES-OAEP with SHA-256 and MGF1-SHA-256, and the default empty label.
    /// The default, and what should be written unless something on the other
    /// side cannot read it.
    #[default]
    OaepSha256,
    /// RSAES-PKCS1-v1_5. Written only on request: its padding is the one the
    /// Bleichenbacher/Marvin attack is about, which is why the reader answers
    /// an unusable block with implicit rejection rather than an error.
    Pkcs1v15,
}

/// Who a document is encrypted for, and how their key is wrapped.
#[derive(Clone, Debug)]
pub struct Encryption {
    /// The recipient certificates, in the order they were given. Each gets
    /// one `KeyTransRecipientInfo` naming it, so any one of their private
    /// keys recovers the document.
    pub recipients: Vec<Recipient>,
    /// The key transport to write for every recipient alike.
    pub key_transport: KeyTransport,
}

/// Encrypt `plaintext` as a DER CMS `ContentInfo` carrying `EnvelopedData`.
///
/// The content-encryption key and the initialisation vector are fresh for
/// every call. The key exists only inside this function and is zeroed when it
/// is dropped; it is never returned, logged, or placed in the result.
pub(crate) fn envelope(plaintext: &[u8], encryption: &Encryption) -> Result<Vec<u8>, Error> {
    if encryption.recipients.is_empty() {
        return Err(Error::new(
            ErrorCode::NoRecipients,
            "encryption was asked for without a recipient certificate",
        ));
    }

    let mut key = Zeroizing::new(vec![0u8; CONTENT_KEY_BYTES]);
    let mut initialisation_vector = [0u8; BLOCK_BYTES];
    // `OsRng` and not a seeded generator: this is the key that protects the
    // document, and it must be unpredictable to everyone including whoever
    // reads this file.
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut initialisation_vector);

    let ciphertext = Aes256CbcEnc::new_from_slices(&key, &initialisation_vector)
        .map_err(|_| encrypt_failed())?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut infos = Vec::with_capacity(encryption.recipients.len());
    for recipient in &encryption.recipients {
        infos.push(RecipientInfo::Ktri(key_trans(
            recipient,
            encryption.key_transport,
            &key,
        )?));
    }

    let enveloped = EnvelopedData {
        // RFC 5652 §6.1: version 0, because there is no `originatorInfo`, no
        // `unprotectedAttrs`, and every `RecipientInfo` is itself version 0.
        version: CmsVersion::V0,
        originator_info: None,
        recip_infos: RecipientInfos(SetOfVec::try_from(infos).map_err(|_| encrypt_failed())?),
        encrypted_content: EncryptedContentInfo {
            content_type: ID_DATA,
            content_enc_alg: content_algorithm(&initialisation_vector)?,
            encrypted_content: Some(OctetString::new(ciphertext).map_err(|_| encrypt_failed())?),
        },
        unprotected_attrs: None,
    };
    let der = enveloped.to_der().map_err(|_| encrypt_failed())?;
    ContentInfo {
        content_type: ID_ENVELOPED_DATA,
        content: Any::from_der(&der).map_err(|_| encrypt_failed())?,
    }
    .to_der()
    .map_err(|_| encrypt_failed())
}

/// One recipient's `KeyTransRecipientInfo`, wrapping `key` for them.
fn key_trans(
    recipient: &Recipient,
    transport: KeyTransport,
    key: &[u8],
) -> Result<KeyTransRecipientInfo, Error> {
    let wrapped = wrap(recipient, transport, key)?;
    Ok(KeyTransRecipientInfo {
        // Version 0 goes with an `issuerAndSerialNumber` identifier; version 2
        // would be required only for `subjectKeyIdentifier`.
        version: CmsVersion::V0,
        rid: recipient.identifier(),
        key_enc_alg: key_transport_algorithm(transport)?,
        enc_key: OctetString::new(wrapped).map_err(|_| encrypt_failed())?,
    })
}

/// Wrap the content-encryption key under one recipient's public key.
///
/// A failure here is almost always the same thing: an RSA modulus too small to
/// carry a 32-byte key plus the padding the chosen transport needs. That is a
/// property of the certificate the caller supplied, so it is reported as
/// [`ErrorCode::UnsupportedRecipientKey`] rather than as an internal fault.
fn wrap(recipient: &Recipient, transport: KeyTransport, key: &[u8]) -> Result<Vec<u8>, Error> {
    let public = recipient.public_key();
    let too_small = || {
        Error::new(
            ErrorCode::UnsupportedRecipientKey,
            format!(
                "a recipient certificate's RSA key is too small to wrap a \
                 {CONTENT_KEY_BYTES} byte content-encryption key"
            ),
        )
    };
    match transport {
        KeyTransport::OaepSha256 => public
            .encrypt(&mut OsRng, rsa::Oaep::new::<sha2::Sha256>(), key)
            .map_err(|_| too_small()),
        KeyTransport::Pkcs1v15 => public
            .encrypt(&mut OsRng, rsa::Pkcs1v15Encrypt, key)
            .map_err(|_| too_small()),
    }
}

/// `RSAES-OAEP-params` (RFC 8017 appendix A.2.1).
///
/// Every field has a DEFAULT, so an absent field means SHA-1, MGF1-SHA-1, and
/// the empty label. Both non-default fields are therefore written explicitly;
/// the label is left at its default, which is what the reader accepts.
#[derive(Sequence)]
struct OaepParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    p_source: Option<AlgorithmIdentifierOwned>,
}

fn sha256_identifier() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA256,
        parameters: Some(Any::null()),
    }
}

fn key_transport_algorithm(transport: KeyTransport) -> Result<AlgorithmIdentifierOwned, Error> {
    match transport {
        // RFC 3370 §3.1: the parameters of `rsaEncryption` are NULL.
        KeyTransport::Pkcs1v15 => Ok(AlgorithmIdentifierOwned {
            oid: RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        }),
        KeyTransport::OaepSha256 => {
            let hash = sha256_identifier();
            let mask_gen = AlgorithmIdentifierOwned {
                oid: ID_MGF1,
                parameters: Some(
                    Any::from_der(&hash.to_der().map_err(|_| encrypt_failed())?)
                        .map_err(|_| encrypt_failed())?,
                ),
            };
            let parameters = OaepParams {
                hash: Some(hash),
                mask_gen: Some(mask_gen),
                p_source: None,
            }
            .to_der()
            .map_err(|_| encrypt_failed())?;
            Ok(AlgorithmIdentifierOwned {
                oid: RSAES_OAEP,
                parameters: Some(Any::from_der(&parameters).map_err(|_| encrypt_failed())?),
            })
        }
    }
}

/// `contentEncryptionAlgorithm`: AES-256-CBC, whose parameters are the IV as
/// an OCTET STRING (RFC 3565 §4.1).
fn content_algorithm(
    initialisation_vector: &[u8; BLOCK_BYTES],
) -> Result<AlgorithmIdentifierOwned, Error> {
    let octets = OctetString::new(initialisation_vector.as_slice())
        .map_err(|_| encrypt_failed())?
        .to_der()
        .map_err(|_| encrypt_failed())?;
    Ok(AlgorithmIdentifierOwned {
        oid: AES_256_CBC,
        parameters: Some(Any::from_der(&octets).map_err(|_| encrypt_failed())?),
    })
}

/// Every DER encoding step above is structurally impossible to fail: the
/// values are built here and are within every bound the encoders check. The
/// code exists so that no branch has to panic, and it names nothing about the
/// caller's inputs.
fn encrypt_failed() -> Error {
    Error::new(
        ErrorCode::EncryptFailed,
        "the CMS EnvelopedData could not be built",
    )
}

#[cfg(test)]
mod tests {
    //! Unit tests for the algorithm identifiers this module writes. The round
    //! trips, which need a real key pair, live in `tests/encryption.rs`.

    use super::*;

    #[test]
    fn pkcs1_key_transport_is_rsa_encryption_with_null_parameters() {
        let algorithm =
            key_transport_algorithm(KeyTransport::Pkcs1v15).expect("the identifier builds");
        assert_eq!(algorithm.oid, RSA_ENCRYPTION);
        assert_eq!(algorithm.parameters, Some(Any::null()));
    }

    #[test]
    fn oaep_key_transport_names_sha256_for_both_the_hash_and_the_mask() {
        let algorithm =
            key_transport_algorithm(KeyTransport::OaepSha256).expect("the identifier builds");
        assert_eq!(algorithm.oid, RSAES_OAEP);
        let parameters: OaepParams = algorithm
            .parameters
            .expect("OAEP carries parameters")
            .decode_as()
            .expect("the parameters are RSAES-OAEP-params");
        assert_eq!(
            parameters.hash.expect("an explicit hash").oid,
            ID_SHA256,
            "the reader defaults an absent hash to SHA-1"
        );
        let mask_gen = parameters.mask_gen.expect("an explicit mask generator");
        assert_eq!(mask_gen.oid, ID_MGF1);
        let mgf_hash: AlgorithmIdentifierOwned = mask_gen
            .parameters
            .expect("MGF1 names its hash")
            .decode_as()
            .expect("the MGF1 parameter is an algorithm identifier");
        assert_eq!(mgf_hash.oid, ID_SHA256);
        // The label stays at its default: the reader accepts only the empty
        // one, and a `pSpecified` field would have to repeat it.
        assert!(parameters.p_source.is_none());
    }

    #[test]
    fn the_content_algorithm_carries_the_initialisation_vector() {
        let iv = [0x5au8; BLOCK_BYTES];
        let algorithm = content_algorithm(&iv).expect("the identifier builds");
        assert_eq!(algorithm.oid, AES_256_CBC);
        let octets: OctetString = algorithm
            .parameters
            .expect("AES-CBC carries an IV")
            .decode_as()
            .expect("the parameter is an octet string");
        assert_eq!(octets.as_bytes(), iv.as_slice());
    }

    #[test]
    fn encryption_without_a_recipient_is_refused() {
        let error = envelope(
            b"x",
            &Encryption {
                recipients: Vec::new(),
                key_transport: KeyTransport::default(),
            },
        )
        .expect_err("nobody could read it");
        assert_eq!(error.code(), ErrorCode::NoRecipients);
    }
}
