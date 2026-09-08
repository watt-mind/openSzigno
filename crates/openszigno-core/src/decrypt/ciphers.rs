//! Content-encryption cipher identification and decryption.
//!
//! This covers the symmetric half of the `encrypt` transform: recognising
//! which of the supported `contentEncryptionAlgorithm` OIDs a CMS message
//! names, and decrypting under it once the content-encryption key and
//! initialisation vector are in hand. AES-128/192/256-CBC are supported
//! unconditionally; DES-EDE3-CBC only when the caller opts in, because it is
//! weak and is merely what the reference implementation defaulted to.

use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use const_oid::ObjectIdentifier;

use crate::Error;

use super::{ErrorCode, decrypt_failed};

const AES_128_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
const AES_192_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.22");
const AES_256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");
const DES_EDE3_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.3.7");

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type TdesCbcDec = cbc::Decryptor<des::TdesEde3>;

#[derive(Clone, Copy)]
pub(super) enum CipherKind {
    Aes128,
    Aes192,
    Aes256,
    TripleDes,
}

pub(super) struct ContentCipher {
    pub(super) kind: CipherKind,
    pub(super) key_bytes: usize,
    pub(super) block_bytes: usize,
    pub(super) legacy: bool,
}

pub(super) fn content_cipher(oid: &ObjectIdentifier) -> Option<ContentCipher> {
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

pub(super) fn decrypt_content(
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
    //! Unit tests for the content-cipher table and CBC/PKCS7 decryption.

    use super::*;

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
}
