//! Decryption of the `encrypt` transform: the supported CMS subset, the
//! reasons a document is skipped instead, and the limits that still apply.

mod common;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::envelope::{
    Cipher, Damage, EncryptedKeyKdf, KeyTransport, Message, Naming, PASSPHRASE, Recipient, Which,
};
use common::{deflated, document, dossier_with, single_member_zip};
use openszigno_core::{
    DecodeOutcome, DecryptOptions, ErrorCode, Limits, RecipientKey, UnsupportedReason,
    decode_document_with, parse,
};

fn recipient() -> Recipient {
    Recipient::new(Which::Recipient, "openSzigno synthetic recipient", true)
}

fn stranger() -> Recipient {
    Recipient::new(Which::Stranger, "openSzigno synthetic stranger", true)
}

fn key_of(recipient: &Recipient) -> RecipientKey {
    RecipientKey::load(
        &recipient.private_pkcs8_der,
        None,
        Some(&recipient.certificate_der),
    )
    .expect("the synthetic recipient key loads")
}

/// A one-document dossier whose payload is `payload` under the given chain.
fn dossier_with_payload(payload: &[u8], transforms: &[&str], source_size: u64) -> String {
    dossier_with(&document(
        1,
        "payload.txt",
        Some("txt"),
        source_size,
        transforms,
        &STANDARD.encode(payload),
    ))
}

fn decode(
    xml: &str,
    key: Option<&RecipientKey>,
    allow_legacy_ciphers: bool,
) -> Result<DecodeOutcome, openszigno_core::Error> {
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");
    decode_document_with(
        &dossier,
        0,
        &Limits::default(),
        &DecryptOptions {
            key,
            allow_legacy_ciphers,
        },
    )
}

fn decoded(outcome: Result<DecodeOutcome, openszigno_core::Error>) -> (Vec<u8>, bool) {
    match outcome.expect("decoding must succeed") {
        DecodeOutcome::Decoded(decoded) => (decoded.bytes, decoded.decrypted),
        DecodeOutcome::Unsupported(reason) => panic!("payload must decode, got {reason:?}"),
    }
}

fn skipped(outcome: Result<DecodeOutcome, openszigno_core::Error>) -> UnsupportedReason {
    match outcome.expect("decoding must not fail") {
        DecodeOutcome::Decoded(_) => panic!("the payload must not decode"),
        DecodeOutcome::Unsupported(reason) => reason,
    }
}

const PLAINTEXT: &[u8] = b"Synthetic e-dossier payload, encrypted for one recipient.\n";

#[test]
fn every_supported_cipher_and_key_transport_round_trips() {
    let recipient = recipient();
    let key = key_of(&recipient);
    for cipher in [Cipher::Aes128Cbc, Cipher::Aes192Cbc, Cipher::Aes256Cbc] {
        for transport in [KeyTransport::Pkcs1v15, KeyTransport::OaepSha256] {
            for naming in [Naming::IssuerAndSerial, Naming::SubjectKeyIdentifier] {
                let message = common::envelope::envelope(
                    &Message {
                        plaintext: PLAINTEXT,
                        cipher,
                        transport,
                        naming,
                    },
                    &recipient,
                );
                let xml =
                    dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);
                let (bytes, decrypted) = decoded(decode(&xml, Some(&key), false));
                assert_eq!(bytes, PLAINTEXT, "{cipher:?} {transport:?} {naming:?}");
                assert!(decrypted, "a decrypted document is reported as decrypted");
            }
        }
    }
}

#[test]
fn a_zip_encrypt_base64_chain_is_reversed_in_the_documented_order() {
    let recipient = recipient();
    let key = key_of(&recipient);
    let archive = single_member_zip("payload.txt", PLAINTEXT, deflated());
    let message = common::envelope::envelope(
        &Message {
            plaintext: &archive,
            cipher: Cipher::Aes256Cbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &recipient,
    );
    let xml = dossier_with_payload(
        &message,
        &["zip", "encrypt", "base64"],
        PLAINTEXT.len() as u64,
    );
    let (bytes, decrypted) = decoded(decode(&xml, Some(&key), false));
    assert_eq!(bytes, PLAINTEXT);
    assert!(decrypted);
}

#[test]
fn an_encrypted_document_stays_skipped_without_a_key() {
    let recipient = recipient();
    let message = common::envelope::envelope(
        &Message {
            plaintext: PLAINTEXT,
            cipher: Cipher::Aes128Cbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &recipient,
    );
    let xml = dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);
    assert_eq!(
        skipped(decode(&xml, None, false)),
        UnsupportedReason::Encrypted
    );
}

#[test]
fn a_document_addressed_to_somebody_else_is_skipped_not_an_error() {
    let recipient = recipient();
    let key = key_of(&recipient);
    let message = common::envelope::envelope(
        &Message {
            plaintext: PLAINTEXT,
            cipher: Cipher::Aes128Cbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &stranger(),
    );
    let xml = dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);
    assert_eq!(
        skipped(decode(&xml, Some(&key), false)),
        UnsupportedReason::NoMatchingRecipient
    );
}

/// A wrapped key only somebody else can unwrap is answered like any other
/// unusable block.
///
/// Under implicit rejection this is not a fixed code either: the recipient's
/// key turns the stranger's ciphertext into a block that does not unpad, so a
/// synthetic key is substituted and the answer comes from
/// `AFTER_SUBSTITUTION`, the same set a malformed block reaches. Asserting
/// the set rather than one code is what keeps this test from depending on
/// what the garbage happened to be.
#[test]
fn the_wrong_key_for_a_matching_recipient_is_a_plain_decryption_failure() {
    // The stranger's certificate names the recipient, but the key that can
    // unwrap the content key is the recipient's. Loading the stranger's key
    // against the recipient's certificate is refused, so the mismatch is
    // produced by naming the recipient and holding a key whose modulus
    // differs: `RecipientKey` binds a key to its own certificate, so the case
    // arrives as a message re-labelled with the recipient's identity.
    let recipient = recipient();
    let stranger = stranger();
    let key = key_of(&recipient);
    let mut message = common::envelope::envelope(
        &Message {
            plaintext: PLAINTEXT,
            cipher: Cipher::Aes128Cbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &recipient,
    );
    let stranger_message = common::envelope::envelope(
        &Message {
            plaintext: PLAINTEXT,
            cipher: Cipher::Aes128Cbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &stranger,
    );
    // Swap in a wrapped key only the stranger can unwrap, leaving the
    // recipient's own identity in place.
    let wrapped = wrapped_key(&message);
    let foreign = wrapped_key(&stranger_message);
    assert_eq!(wrapped.len(), foreign.len());
    let at = find(&message, &wrapped).expect("the wrapped key is in the message");
    message[at..at + foreign.len()].copy_from_slice(&foreign);

    let xml = dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);
    let answer = outcome(decode(&xml, Some(&key), false));
    assert!(answer.is_err(), "the wrong key must fail");
    assert_says_nothing(&answer, "a stranger's wrapped key");
}

/// The codes the decode path may legitimately reach once an unusable
/// content-encryption key has been substituted.
///
/// Implicit rejection moves the failure downstream instead of reporting it,
/// so the outcome is whatever the content cipher and the checks after it make
/// of a plaintext decrypted under the wrong key. Almost always the CBC PKCS#7
/// padding is invalid and that is `decrypt_failed`; roughly once in 256 the
/// padding happens to be valid, the "plaintext" is garbage of some other
/// length, and the declared source size is what rejects it. Both are answers
/// about the document, neither is an answer about the wrapped key, and which
/// of the two a given dossier gets is a property of that dossier, not of the
/// step that failed.
const AFTER_SUBSTITUTION: [ErrorCode; 2] =
    [ErrorCode::DecryptFailed, ErrorCode::SourceSizeMismatch];

/// Words that would give the game away if they ever reached a message.
const TELLTALE: [&str; 6] = [
    "pad",
    "wrap",
    "unwrap",
    "rsa",
    "recipient key",
    "key transport",
];

/// What one dossier turned into, reduced to what a caller can actually see.
fn outcome(
    result: Result<DecodeOutcome, openszigno_core::Error>,
) -> Result<usize, (ErrorCode, String)> {
    match result {
        Ok(DecodeOutcome::Decoded(decoded)) => Ok(decoded.bytes.len()),
        Ok(DecodeOutcome::Unsupported(reason)) => panic!("unexpected skip: {reason:?}"),
        Err(error) => Err((error.code(), error.message().to_owned())),
    }
}

fn assert_says_nothing(outcome: &Result<usize, (ErrorCode, String)>, case: &str) {
    let Err((code, message)) = outcome else {
        return;
    };
    assert!(
        AFTER_SUBSTITUTION.contains(code),
        "{case}: {code:?} is outside the set an unusable key may produce"
    );
    let lowered = message.to_lowercase();
    for word in TELLTALE {
        assert!(
            !lowered.contains(word),
            "{case}: the message names {word:?}, which describes the failing step"
        );
    }
}

/// A malformed wrapped key and a well-formed wrap of the wrong key must be
/// answered from the same closed set.
///
/// This is the whole point of implicit rejection. The first block does not
/// unpad and is replaced by a synthetic key; the second unpads perfectly and
/// is simply not the key the content was encrypted under. If the recipient
/// ever answered those two differently -- a different code, a message naming
/// the padding or the wrapped key, one failing where the other did not -- the
/// difference would be a Bleichenbacher oracle, because the attacker chose
/// which of the two to send.
///
/// The assertion is about the *set* the answers come from, not one fixed
/// code, because what a substituted key produces downstream depends on the
/// garbage it decrypts to. Both messages are seeded and so identical on every
/// platform, but pinning one code would be pinning an accident of the
/// garbage rather than the property under test.
#[test]
fn a_malformed_wrapped_key_and_a_well_formed_wrong_one_are_one_answer() {
    let recipient = recipient();
    let key = key_of(&recipient);
    for cipher in [Cipher::Aes128Cbc, Cipher::Aes192Cbc, Cipher::Aes256Cbc] {
        for transport in [KeyTransport::Pkcs1v15, KeyTransport::OaepSha256] {
            let message = Message {
                plaintext: PLAINTEXT,
                cipher,
                transport,
                naming: Naming::IssuerAndSerial,
            };
            let intact = common::envelope::envelope(&message, &recipient);
            let wrapped = wrapped_key(&intact);
            let at = find(&intact, &wrapped).expect("the wrapped key is in the message");

            // One byte of the RSA ciphertext flipped: the block will not
            // unpad, and the substitution happens.
            let mut malformed = intact.clone();
            malformed[at + 100] ^= 0x01;

            // A key of exactly the right length for the announced cipher,
            // wrapped in valid padding for this very recipient. It unpads,
            // and it is still the wrong key.
            let mut wrong = intact.clone();
            let replacement = common::envelope::wrap_bytes(
                &recipient,
                transport,
                &common::envelope::filler(key_bytes(cipher), 0x3c),
            );
            assert_eq!(replacement.len(), wrapped.len());
            wrong[at..at + replacement.len()].copy_from_slice(&replacement);

            let case = format!("{cipher:?} {transport:?}");
            let answers: Vec<_> = [&malformed, &wrong]
                .into_iter()
                .map(|body| {
                    let xml =
                        dossier_with_payload(body, &["encrypt", "base64"], PLAINTEXT.len() as u64);
                    outcome(decode(&xml, Some(&key), false))
                })
                .collect();
            for (which, answer) in ["a malformed block", "a well-formed wrong key"]
                .into_iter()
                .zip(answers.iter())
            {
                assert_says_nothing(answer, &format!("{case}: {which}"));
                assert!(
                    answer.is_err(),
                    "{case}: {which} must not decode to the real plaintext"
                );
            }
        }
    }
}

/// A content key that unpads cleanly but is the wrong length for the
/// announced cipher goes down the same path as any other unusable block.
#[test]
fn a_content_key_of_the_wrong_length_is_not_a_separate_answer() {
    let recipient = recipient();
    let key = key_of(&recipient);
    for cipher in [Cipher::Aes128Cbc, Cipher::Aes192Cbc, Cipher::Aes256Cbc] {
        let message = common::envelope::damaged(
            &Message {
                plaintext: PLAINTEXT,
                cipher,
                transport: KeyTransport::Pkcs1v15,
                naming: Naming::IssuerAndSerial,
            },
            &recipient,
            Damage::MismatchedContentKeyLength,
        );
        let xml = dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);
        let answer = outcome(decode(&xml, Some(&key), false));
        assert_says_nothing(&answer, &format!("{cipher:?}"));
        assert!(answer.is_err(), "{cipher:?}: a wrong-length key must fail");
    }
}

/// Substitution is deterministic: the same dossier decrypted twice with the
/// same key gives the same answer, so a repeat submission tells an attacker
/// nothing a single one did not.
#[test]
fn an_unusable_wrapped_key_gives_the_same_answer_every_time() {
    let recipient = recipient();
    let key = key_of(&recipient);
    for offset in [7usize, 100, 200] {
        let mut message = common::envelope::envelope(
            &Message {
                plaintext: PLAINTEXT,
                cipher: Cipher::Aes256Cbc,
                transport: KeyTransport::Pkcs1v15,
                naming: Naming::IssuerAndSerial,
            },
            &recipient,
        );
        let wrapped = wrapped_key(&message);
        let at = find(&message, &wrapped).expect("the wrapped key is in the message");
        message[at + offset] ^= 0xff;
        let xml = dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);

        let first = outcome(decode(&xml, Some(&key), false));
        let second = outcome(decode(&xml, Some(&key), false));
        assert_eq!(
            first, second,
            "offset {offset}: the same input must give the same outcome"
        );
        assert_says_nothing(&first, &format!("offset {offset}"));
    }
}

/// The key length the announced content cipher takes.
fn key_bytes(cipher: Cipher) -> usize {
    match cipher {
        Cipher::Aes128Cbc => 16,
        Cipher::Aes192Cbc | Cipher::TripleDesCbc => 24,
        Cipher::Aes256Cbc | Cipher::Unsupported => 32,
    }
}

/// The `encryptedKey` OCTET STRING of a synthetic message: the last 256 bytes
/// of an RSA-2048 wrap, which the builder places before the encrypted content.
fn wrapped_key(message: &[u8]) -> Vec<u8> {
    let marker = [0x04u8, 0x82, 0x01, 0x00];
    let at = find(message, &marker).expect("the message wraps a 256-byte key");
    message[at + marker.len()..at + marker.len() + 256].to_vec()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn a_malformed_cms_payload_is_an_error_not_a_skip() {
    let recipient = recipient();
    let key = key_of(&recipient);
    for payload in [
        b"not DER at all".to_vec(),
        vec![0x30, 0x80, 0x02, 0x01, 0x00],
    ] {
        let xml = dossier_with_payload(&payload, &["encrypt", "base64"], PLAINTEXT.len() as u64);
        let error = decode(&xml, Some(&key), false).expect_err("malformed CMS must fail");
        assert_eq!(error.code(), ErrorCode::InvalidCms);
    }
}

#[test]
fn a_legacy_cipher_is_refused_by_default_and_accepted_behind_the_flag() {
    let recipient = recipient();
    let key = key_of(&recipient);
    let message = common::envelope::envelope(
        &Message {
            plaintext: PLAINTEXT,
            cipher: Cipher::TripleDesCbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &recipient,
    );
    let xml = dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);
    assert_eq!(
        skipped(decode(&xml, Some(&key), false)),
        UnsupportedReason::LegacyCipher {
            oid: "1.2.840.113549.3.7".to_owned()
        }
    );
    let (bytes, decrypted) = decoded(decode(&xml, Some(&key), true));
    assert_eq!(bytes, PLAINTEXT);
    assert!(decrypted);
}

#[test]
fn an_unsupported_algorithm_is_skipped_with_its_oid_named() {
    let recipient = recipient();
    let key = key_of(&recipient);
    let message = common::envelope::envelope(
        &Message {
            plaintext: PLAINTEXT,
            cipher: Cipher::Unsupported,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &recipient,
    );
    let xml = dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);
    assert_eq!(
        skipped(decode(&xml, Some(&key), true)),
        UnsupportedReason::UnsupportedCipher {
            oid: "1.2.840.113549.1.9.16.3.18".to_owned()
        }
    );
}

#[test]
fn a_decrypted_document_is_bounded_by_the_decoded_size_limit() {
    let recipient = recipient();
    let key = key_of(&recipient);
    let plaintext = vec![b'x'; 4096];
    let message = common::envelope::envelope(
        &Message {
            plaintext: &plaintext,
            cipher: Cipher::Aes128Cbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &recipient,
    );
    let xml = dossier_with_payload(&message, &["encrypt", "base64"], plaintext.len() as u64);
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");
    let limits = Limits {
        max_decoded_document_bytes: 1024,
        ..Limits::default()
    };
    let error = decode_document_with(
        &dossier,
        0,
        &limits,
        &DecryptOptions {
            key: Some(&key),
            allow_legacy_ciphers: false,
        },
    )
    .expect_err("an oversize payload must fail");
    assert_eq!(error.code(), ErrorCode::DecodedTooLarge);
}

#[test]
fn a_passphrase_protected_pkcs8_key_loads_with_the_right_passphrase_only() {
    let recipient = recipient();
    // Both PBES2 key derivations a real `.p12` conversion can produce:
    // PBKDF2-SHA-256, which `openssl pkcs8 -topk8` writes, and scrypt.
    for kdf in [EncryptedKeyKdf::Pbkdf2, EncryptedKeyKdf::Scrypt] {
        let loaded = RecipientKey::load(
            recipient.encrypted_key_pem_with(kdf).as_bytes(),
            Some(PASSPHRASE.as_bytes()),
            Some(&recipient.certificate_der),
        );
        assert!(loaded.is_ok(), "{kdf:?} with the right passphrase loads");
    }
    let encrypted = recipient.encrypted_key_pem();

    for passphrase in [None, Some(b"wrong".as_slice())] {
        let error = RecipientKey::load(
            encrypted.as_bytes(),
            passphrase,
            Some(&recipient.certificate_der),
        )
        .expect_err("a wrong or missing passphrase must fail");
        assert_eq!(error.code(), ErrorCode::InvalidDecryptionKey);
        assert!(
            !error.message().contains("wrong") && !error.message().contains(PASSPHRASE),
            "the message must not echo the passphrase"
        );
    }
}

#[test]
fn a_pem_bundle_supplies_its_own_certificate_and_a_bare_key_does_not() {
    let recipient = recipient();
    RecipientKey::load(recipient.pem_bundle().as_bytes(), None, None)
        .expect("a key and certificate bundle loads on its own");

    let error = RecipientKey::load(&recipient.private_pkcs8_der, None, None)
        .expect_err("a bare key names no recipient");
    assert_eq!(error.code(), ErrorCode::DecryptionCertificateRequired);
}

#[test]
fn a_certificate_that_does_not_belong_to_the_key_is_refused() {
    let recipient = recipient();
    let stranger = stranger();
    let error = RecipientKey::load(
        &recipient.private_pkcs8_der,
        None,
        Some(&stranger.certificate_der),
    )
    .expect_err("a foreign certificate must be refused");
    assert_eq!(error.code(), ErrorCode::DecryptionKeyMismatch);
}

#[test]
fn a_certificate_without_a_subject_key_identifier_cannot_match_an_ski_recipient() {
    let plain = Recipient::new(Which::Recipient, "openSzigno synthetic recipient", false);
    let with_identifier = recipient();
    let key = RecipientKey::load(&plain.private_pkcs8_der, None, Some(&plain.certificate_der))
        .expect("the key loads");
    let message = common::envelope::envelope(
        &Message {
            plaintext: PLAINTEXT,
            cipher: Cipher::Aes128Cbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::SubjectKeyIdentifier,
        },
        &with_identifier,
    );
    let xml = dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);
    assert_eq!(
        skipped(decode(&xml, Some(&key), false)),
        UnsupportedReason::NoMatchingRecipient
    );
}

#[test]
fn an_unsupported_chain_containing_encrypt_is_still_an_unsupported_chain() {
    let recipient = recipient();
    let key = key_of(&recipient);
    let xml = dossier_with_payload(b"anything", &["encrypt", "zip", "base64"], 8);
    assert_eq!(
        skipped(decode(&xml, Some(&key), false)),
        UnsupportedReason::TransformChain
    );
}

#[test]
fn an_unsupported_key_transport_algorithm_is_skipped_with_its_oid_named() {
    let recipient = recipient();
    let key = key_of(&recipient);
    let message = common::envelope::envelope(
        &Message {
            plaintext: PLAINTEXT,
            cipher: Cipher::Aes128Cbc,
            transport: KeyTransport::UnsupportedOid,
            naming: Naming::IssuerAndSerial,
        },
        &recipient,
    );
    let xml = dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);
    assert_eq!(
        skipped(decode(&xml, Some(&key), false)),
        UnsupportedReason::UnsupportedCipher {
            oid: "1.2.840.10045.2.1".to_owned()
        }
    );
}

#[test]
fn framing_a_real_encryptor_would_not_produce_is_malformed_cms() {
    let recipient = recipient();
    let key = key_of(&recipient);
    for damage in [
        Damage::NoEncryptedContent,
        Damage::ShortInitialisationVector,
        Damage::NoInitialisationVector,
    ] {
        let message = common::envelope::damaged(
            &Message {
                plaintext: PLAINTEXT,
                cipher: Cipher::Aes128Cbc,
                transport: KeyTransport::Pkcs1v15,
                naming: Naming::IssuerAndSerial,
            },
            &recipient,
            damage,
        );
        let xml = dossier_with_payload(&message, &["encrypt", "base64"], PLAINTEXT.len() as u64);
        let error = decode(&xml, Some(&key), false).expect_err("{damage:?} must fail");
        assert_eq!(error.code(), ErrorCode::InvalidCms, "{damage:?}");
    }
}

#[test]
fn a_ciphertext_larger_than_the_limit_is_refused_before_it_is_decrypted() {
    // The ciphertext is bigger than the limit while the plaintext would not
    // be, so this can only be the pre-allocation check.
    let recipient = recipient();
    let key = key_of(&recipient);
    let plaintext = vec![b'y'; 2048];
    let message = common::envelope::envelope(
        &Message {
            plaintext: &plaintext,
            cipher: Cipher::Aes128Cbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &recipient,
    );
    let xml = dossier_with_payload(&message, &["encrypt", "base64"], plaintext.len() as u64);
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");
    let limits = Limits {
        max_decoded_document_bytes: 2047,
        ..Limits::default()
    };
    let error = decode_document_with(
        &dossier,
        0,
        &limits,
        &DecryptOptions {
            key: Some(&key),
            allow_legacy_ciphers: false,
        },
    )
    .expect_err("an oversize ciphertext must fail");
    assert_eq!(error.code(), ErrorCode::DecodedTooLarge);
}

#[test]
fn a_der_certificate_works_as_well_as_a_pem_one() {
    let recipient = recipient();
    RecipientKey::load(
        recipient.key_pem().as_bytes(),
        None,
        Some(&recipient.certificate_der),
    )
    .expect("a PEM key with a DER certificate loads");
    RecipientKey::load(
        &recipient.private_pkcs8_der,
        None,
        Some(recipient.certificate_pem().as_bytes()),
    )
    .expect("a DER key with a PEM certificate loads");
}

#[test]
fn a_document_index_outside_the_dossier_is_refused() {
    let xml = dossier_with_payload(b"anything", &["base64"], 8);
    let dossier = parse(xml.as_bytes(), &Limits::default()).expect("the dossier parses");
    let error = decode_document_with(&dossier, 7, &Limits::default(), &DecryptOptions::default())
        .expect_err("there is no document 7");
    assert_eq!(error.code(), ErrorCode::InvalidAttribute);
}
