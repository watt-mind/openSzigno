//! RSA key transport with implicit rejection.
//!
//! The RSA ciphertext this module decrypts is the CMS `RecipientInfo`'s
//! encrypted content-encryption key, and it comes straight out of an
//! untrusted dossier. A caller who can submit chosen dossiers to the same key
//! and observe whether decryption succeeded, or how long it took, is exactly
//! the attacker a Bleichenbacher/Marvin-style chosen-ciphertext attack against
//! RSAES-PKCS1-v1_5 needs (RUSTSEC-2023-0071).
//!
//! The defence here is **implicit rejection**, the mitigation OpenSSL 3.2+
//! spells `RSA_PKCS1_IMPLICIT_REJECTION` and Go's `crypto/rsa` applies
//! unconditionally, and the one RFC 5246 §7.4.7.1 prescribes for the same
//! problem in TLS: never report that unpadding failed. Instead:
//!
//! 1. the private operation runs once, blinded, and its raw plaintext block
//!    is unpadded here rather than by the `rsa` crate;
//! 2. every PKCS#1 v1.5 type 2 check accumulates into one [`Choice`] with no
//!    early return and no data-dependent branch;
//! 3. an unusable block is replaced by a deterministic **synthetic** key
//!    derived from a per-key secret over the ciphertext, chosen with
//!    `conditional_select`, so both paths execute identically;
//! 4. the caller continues into symmetric decryption unconditionally, and a
//!    substituted key surfaces as the same undifferentiated `decrypt_failed`
//!    that a tampered content ciphertext produces.
//!
//! What this removes is the padding oracle carried by control flow, by the
//! error surface, and by the coarse timing difference between "stopped at the
//! unpad" and "ran the whole content cipher". What it does not remove is the
//! non-constant-time modular exponentiation inside `rsa` 0.9 (blinding masks
//! it, `rsa` 0.10 fixes it) and the leading-zero-dependent big-integer to
//! byte-string conversion that version's API forces. See `deny.toml`.
//!
//! Nothing here may return an error, and nothing here may print, store, or
//! otherwise expose the derivation secret or either candidate key.

use hmac::{Hmac, Mac};
use rsa::RsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

/// Domain separation for the synthetic-key derivation, so the per-key secret
/// this file computes can never collide with any other use of the key.
const DOMAIN: &[u8] = b"openszigno/cms/implicit-rejection/v1";

/// The HMAC-SHA-256 tag length, and so the size of one derivation block.
const TAG_BYTES: usize = 32;

/// Unwrap an RSAES-PKCS1-v1_5 encrypted content-encryption key, substituting a
/// synthetic key rather than reporting that the padding was unusable.
///
/// The result is always exactly `key_bytes` long, so the caller has no length
/// to branch on either.
pub(super) fn unwrap_pkcs1v15(
    private: &RsaPrivateKey,
    ciphertext: &[u8],
    key_bytes: usize,
) -> Zeroizing<Vec<u8>> {
    let synthetic = synthetic_key(private, ciphertext, key_bytes);
    let modulus_bytes = private.size();
    // Public parameters only. A modulus too small to hold `0x00 0x02`, eight
    // padding bytes, the `0x00` separator and a key of this length cannot
    // carry this block at all, and both lengths are known to whoever built
    // the dossier, so deciding it here leaks nothing about the plaintext.
    // Passing it also guarantees the padding run below is at least eight
    // bytes, which is why no separate length check appears in `unpad`.
    if modulus_bytes < key_bytes + 11 {
        return synthetic;
    }
    let block = private_operation(private, ciphertext, modulus_bytes);
    let (usable, candidate) = unpad(&block, key_bytes);
    select(&candidate, &synthetic, usable)
}

/// Unwrap an RSAES-OAEP encrypted content-encryption key.
///
/// OAEP is not the padding the Marvin attack is about, and `rsa` 0.9 unpads it
/// itself, so this is not a constant-time implementation of OAEP. It is here
/// so that both key-transport algorithms hand the caller a key of the expected
/// length and never a distinguishable failure: the recovered key is replaced
/// by the same synthetic key when unpadding failed or produced the wrong
/// length.
pub(super) fn unwrap_oaep(
    private: &RsaPrivateKey,
    padding: rsa::Oaep,
    ciphertext: &[u8],
    key_bytes: usize,
) -> Zeroizing<Vec<u8>> {
    let synthetic = synthetic_key(private, ciphertext, key_bytes);
    let mut rng = rand_core::OsRng;
    let recovered = Zeroizing::new(
        private
            .decrypt_blinded(&mut rng, padding, ciphertext)
            .unwrap_or_default(),
    );
    let usable = recovered.len().ct_eq(&key_bytes);
    let mut candidate = Zeroizing::new(vec![0u8; key_bytes]);
    let copied = recovered.len().min(key_bytes);
    candidate[..copied].copy_from_slice(&recovered[..copied]);
    select(&candidate, &synthetic, usable)
}

/// The blinded RSA private operation, as a big-endian block of exactly
/// `modulus_bytes`.
///
/// `rsa::hazmat::rsa_decrypt_and_check` is the lowest-level blinded private
/// operation `rsa` 0.9.10 exposes: it applies the same `OsRng` blinding factor
/// `RsaPrivateKey::decrypt_blinded` does and verifies the CRT result by
/// re-encrypting, but it returns the raw plaintext instead of unpadding it.
/// Every way it can fail (a ciphertext that is not `modulus_bytes` long, one
/// numerically at or above the modulus, a CRT fault) is a property of the
/// ciphertext the sender can see for itself, and each yields an all-zero block
/// here, which the unpadding below rejects like any other unusable block.
fn private_operation(
    private: &RsaPrivateKey,
    ciphertext: &[u8],
    modulus_bytes: usize,
) -> Zeroizing<Vec<u8>> {
    let mut block = Zeroizing::new(vec![0u8; modulus_bytes]);
    if ciphertext.len() != modulus_bytes {
        return block;
    }
    let mut rng = rand_core::OsRng;
    let encoded = rsa::BigUint::from_bytes_be(ciphertext);
    let Ok(plaintext) = rsa::hazmat::rsa_decrypt_and_check(private, Some(&mut rng), &encoded)
    else {
        return block;
    };
    let bytes = Zeroizing::new(plaintext.to_bytes_be());
    // The plaintext is strictly below the modulus, so it always fits; the
    // saturating subtraction is belt and braces rather than a real case.
    let start = modulus_bytes.saturating_sub(bytes.len());
    block[start..].copy_from_slice(&bytes[bytes.len() - (modulus_bytes - start)..]);
    block
}

/// Check the PKCS#1 v1.5 type 2 framing and take the trailing `key_bytes`.
///
/// `block` is `0x00 || 0x02 || PS || 0x00 || K`, and a key of the announced
/// length pins `K` to the last `key_bytes` bytes, so the separator sits at a
/// fixed, public offset. Every check folds into one [`Choice`]: there is no
/// branch on a plaintext byte, and the candidate is returned whether it is
/// usable or not. The caller's `modulus_bytes >= key_bytes + 11`
/// precondition is what makes the padding run at least eight bytes long.
fn unpad(block: &[u8], key_bytes: usize) -> (Choice, Zeroizing<Vec<u8>>) {
    let separator = block.len() - key_bytes - 1;
    let mut usable = block[0].ct_eq(&0x00) & block[1].ct_eq(&0x02) & block[separator].ct_eq(&0x00);
    for byte in &block[2..separator] {
        usable &= !byte.ct_eq(&0x00);
    }
    (usable, Zeroizing::new(block[separator + 1..].to_vec()))
}

/// `candidate` when `usable`, else `fallback`, byte by byte.
fn select(candidate: &[u8], fallback: &[u8], usable: Choice) -> Zeroizing<Vec<u8>> {
    let mut chosen = Zeroizing::new(vec![0u8; candidate.len()]);
    for (slot, (from_block, from_secret)) in chosen
        .iter_mut()
        .zip(candidate.iter().zip(fallback.iter()))
    {
        *slot = u8::conditional_select(from_secret, from_block, usable);
    }
    chosen
}

/// The key an unusable block is silently replaced with.
///
/// It is HMAC-SHA-256 over the ciphertext under a secret only the holder of
/// the private key can compute, so it is stable for one `(key, ciphertext)`
/// pair and unpredictable to whoever submitted the ciphertext: an attacker
/// cannot tell the substitution from a real unwrap by replaying a dossier, and
/// cannot precompute what the substitution will be. Counter blocks let it
/// cover a key longer than one tag, which no supported cipher needs today.
pub(super) fn synthetic_key(
    private: &RsaPrivateKey,
    ciphertext: &[u8],
    key_bytes: usize,
) -> Zeroizing<Vec<u8>> {
    let secret = derivation_secret(private);
    let mut derived = Zeroizing::new(vec![0u8; key_bytes]);
    for (counter, chunk) in derived.chunks_mut(TAG_BYTES).enumerate() {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_slice()).expect("HMAC takes any key length");
        mac.update(DOMAIN);
        mac.update(&(counter as u64).to_be_bytes());
        mac.update(&(key_bytes as u64).to_be_bytes());
        mac.update(ciphertext);
        let mut tag = Zeroizing::new([0u8; TAG_BYTES]);
        tag.copy_from_slice(&mac.finalize().into_bytes());
        chunk.copy_from_slice(&tag[..chunk.len()]);
    }
    derived
}

/// The per-key HMAC secret: a hash of the private exponent and the primes.
///
/// It never leaves this file, is never stored between calls, and is zeroed on
/// drop. Recomputing it per unwrap costs one SHA-256 over a few hundred bytes.
fn derivation_secret(private: &RsaPrivateKey) -> Zeroizing<[u8; TAG_BYTES]> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(Zeroizing::new(private.d().to_bytes_be()).as_slice());
    for prime in private.primes() {
        hasher.update(Zeroizing::new(prime.to_bytes_be()).as_slice());
    }
    Zeroizing::new(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    //! Unit tests for the constant-time unpadding, the selection, and the
    //! synthetic-key derivation. The round trips through a whole CMS message
    //! live in `tests/decryption.rs`.

    use super::*;

    /// A block of `modulus_bytes` carrying `key` in valid type 2 padding.
    fn padded(modulus_bytes: usize, key: &[u8]) -> Vec<u8> {
        let mut block = vec![0u8; modulus_bytes];
        block[1] = 0x02;
        let separator = modulus_bytes - key.len() - 1;
        for byte in &mut block[2..separator] {
            *byte = 0xa5;
        }
        block[separator] = 0x00;
        block[separator + 1..].copy_from_slice(key);
        block
    }

    #[test]
    fn a_well_formed_block_unpads_to_the_announced_key_length() {
        let key: Vec<u8> = (0..32u8).collect();
        let (usable, candidate) = unpad(&padded(256, &key), 32);
        assert!(bool::from(usable), "valid type 2 padding must be accepted");
        assert_eq!(candidate.as_slice(), key.as_slice());
    }

    #[test]
    fn every_framing_fault_is_rejected_and_still_yields_a_candidate() {
        let key: Vec<u8> = (0..16u8).collect();
        for (case, offset, value) in [
            ("a first byte that is not 0x00", 0usize, 0x01u8),
            ("a second byte that is not 0x02", 1, 0x01),
            ("a zero inside the padding run", 100, 0x00),
            ("a padding run shorter than eight bytes", 2, 0x00),
            ("a separator that is not 0x00", 256 - 16 - 1, 0xff),
        ] {
            let mut block = padded(256, &key);
            block[offset] = value;
            let (usable, candidate) = unpad(&block, 16);
            assert!(!bool::from(usable), "{case} must be rejected");
            assert_eq!(candidate.len(), 16, "{case} still produces a candidate");
        }
    }

    #[test]
    fn a_payload_of_the_wrong_length_shifts_the_separator_and_is_rejected() {
        // A block padded for a 32-byte key, read as though the announced
        // cipher wanted 16: the separator is then in the middle of the key.
        let key: Vec<u8> = (1..=32u8).collect();
        let (usable, candidate) = unpad(&padded(256, &key), 16);
        assert!(
            !bool::from(usable),
            "a key of the wrong length must not unpad"
        );
        assert_eq!(candidate.len(), 16);
    }

    /// Two distinct keys, generated once for the whole module's tests. The
    /// seed is fixed so the suite is deterministic; nothing is committed.
    fn keys() -> &'static [RsaPrivateKey; 2] {
        use rand_core::SeedableRng as _;
        static KEYS: std::sync::LazyLock<[RsaPrivateKey; 2]> = std::sync::LazyLock::new(|| {
            let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x006F_7065_6E53_5A01);
            [
                RsaPrivateKey::new(&mut rng, 2048).expect("a synthetic key generates"),
                RsaPrivateKey::new(&mut rng, 2048).expect("a synthetic key generates"),
            ]
        });
        &KEYS
    }

    #[test]
    fn the_synthetic_key_is_stable_per_key_and_ciphertext_and_nothing_else() {
        let [first, second] = keys();
        let ciphertext = [0x11u8; 256];
        let other = [0x12u8; 256];

        let baseline = synthetic_key(first, &ciphertext, 32);
        assert_eq!(baseline.len(), 32, "the length the caller asked for");
        assert_eq!(
            synthetic_key(first, &ciphertext, 32).as_slice(),
            baseline.as_slice(),
            "the same key and ciphertext must derive the same substitute"
        );
        assert_ne!(
            synthetic_key(first, &other, 32).as_slice(),
            baseline.as_slice(),
            "a different ciphertext must derive a different substitute"
        );
        assert_ne!(
            synthetic_key(second, &ciphertext, 32).as_slice(),
            baseline.as_slice(),
            "a different private key must derive a different substitute"
        );
        // A shorter key is not a prefix of a longer one: the length is bound
        // into the derivation.
        let short = synthetic_key(first, &ciphertext, 16);
        assert_eq!(short.len(), 16);
        assert_ne!(short.as_slice(), &baseline[..16]);
    }

    #[test]
    fn an_unusable_ciphertext_still_yields_a_key_of_the_announced_length() {
        let [private, _] = keys();
        for (case, ciphertext) in [
            ("a ciphertext of the wrong length", vec![0x00; 8]),
            ("a ciphertext that is not a valid block", vec![0x01; 256]),
        ] {
            for key_bytes in [16usize, 24, 32] {
                let unwrapped = unwrap_pkcs1v15(private, &ciphertext, key_bytes);
                assert_eq!(unwrapped.len(), key_bytes, "{case}");
                assert_eq!(
                    unwrapped.as_slice(),
                    synthetic_key(private, &ciphertext, key_bytes).as_slice(),
                    "{case} must be answered with the synthetic key"
                );
            }
        }
        // A modulus too small to carry the block is the same answer.
        let unwrapped = unwrap_pkcs1v15(private, &[0x01; 256], 256);
        assert_eq!(unwrapped.len(), 256);
    }

    #[test]
    fn selection_takes_the_candidate_only_when_the_block_was_usable() {
        let candidate = [1u8; 16];
        let fallback = [2u8; 16];
        assert_eq!(
            select(&candidate, &fallback, Choice::from(1)).as_slice(),
            &candidate
        );
        assert_eq!(
            select(&candidate, &fallback, Choice::from(0)).as_slice(),
            &fallback
        );
    }
}
