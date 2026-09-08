//! CMS `ContentInfo` / `EnvelopedData` / `RecipientInfo` parsing and
//! validation.
//!
//! This covers the ASN.1 structure of the encrypted payload up to the point
//! where a content-encryption key has been recovered: recognising
//! `EnvelopedData` (and naming, rather than rejecting, `AuthEnvelopedData`),
//! and unwrapping a `KeyTransRecipientInfo`'s encrypted key with
//! RSAES-PKCS1-v1_5 or RSAES-OAEP.

use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, KeyTransRecipientInfo};
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Sequence};
use rsa::RsaPrivateKey;
use x509_cert::spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use crate::Error;

use super::{CmsOutcome, ErrorCode, decrypt_failed, invalid_cms};

/// RFC 5652 §3: the `ContentInfo` content types this module can be handed.
pub(super) const ID_ENVELOPED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
/// RFC 5083 `id-ct-authEnvelopedData`, recognised only to say it is not supported.
pub(super) const ID_AUTH_ENVELOPED_DATA: ObjectIdentifier =
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

/// Decode `payload` as a DER `ContentInfo` and require `id-envelopedData`,
/// naming rather than rejecting `id-ct-authEnvelopedData`.
///
/// The inner `Result` carries a [`CmsOutcome`] instead of the `EnvelopedData`
/// when the content type is recognised but not one this module decrypts; the
/// outer `Result` is reserved for a genuine parse failure.
pub(super) fn parse_content_info(
    payload: &[u8],
) -> Result<Result<EnvelopedData, CmsOutcome>, Error> {
    let content_info = ContentInfo::from_der(payload).map_err(|_| invalid_cms())?;
    if content_info.content_type == ID_AUTH_ENVELOPED_DATA {
        return Ok(Err(CmsOutcome::UnsupportedAlgorithm(
            ID_AUTH_ENVELOPED_DATA.to_string(),
        )));
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
    Ok(Ok(enveloped))
}

pub(super) enum Unwrapped {
    Key(Zeroizing<Vec<u8>>),
    UnsupportedAlgorithm(String),
}

pub(super) fn unwrap_key(
    recipient: &KeyTransRecipientInfo,
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

#[cfg(test)]
mod tests {
    //! Unit tests for RSAES-OAEP parameter handling.
    //!
    //! The round trips live in `tests/decryption.rs`, which can build whole
    //! synthetic messages. These cover the branches that a well-formed message
    //! from a cooperating sender never reaches: algorithm identifiers outside
    //! the subset, and framing a real encryptor would not produce.

    use der::Encode;
    use der::asn1::Any;

    use super::*;

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
}
