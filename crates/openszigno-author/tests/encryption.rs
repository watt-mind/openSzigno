//! Round trips for the `encrypt` transform: what this crate writes is what
//! `openszigno-core` reads back.
//!
//! Every key and certificate here is generated at run time from a fixed seed.
//! No private key, in any encoding, is stored in this repository: a secret
//! scanner cannot tell a real key from a synthetic one, and the project does
//! not allowlist scanner rules, so the only safe amount of key material in the
//! tree is none. See `SECURITY.md`.

use std::sync::LazyLock;

use openszigno_author::{
    DocumentSpec, DossierSpec, Encryption, ErrorCode, KeyTransport, Recipient, build,
};
use openszigno_core::{DecodeOutcome, DecryptOptions, Limits, RecipientKey, decode_document_with};
use rand_core::SeedableRng as _;
use rsa::pkcs8::EncodePrivateKey as _;

const CREATED: &str = "2026-01-01T00:00:00Z";
const PLAINTEXT: &[u8] = b"A payload only a recipient's private key can read.\n";

/// The seed every synthetic key here comes from. Any fixed value would do; a
/// fixed one makes a failure reproduce exactly.
const SEED: u64 = 0x006F_7065_6E53_5A10;

/// Which of the two synthetic key pairs a party is built on.
#[derive(Clone, Copy)]
enum Which {
    Recipient,
    Stranger,
}

/// Both keys, generated once per test binary: RSA generation is bignum
/// arithmetic and costs about 75 ms per key even with the optimized profile.
fn key(which: Which) -> &'static rsa::RsaPrivateKey {
    static KEYS: LazyLock<[rsa::RsaPrivateKey; 2]> = LazyLock::new(|| {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(SEED);
        [
            rsa::RsaPrivateKey::new(&mut rng, 2048).expect("a synthetic RSA key generates"),
            rsa::RsaPrivateKey::new(&mut rng, 2048).expect("a synthetic RSA key generates"),
        ]
    });
    match which {
        Which::Recipient => &KEYS[0],
        Which::Stranger => &KEYS[1],
    }
}

/// One synthetic party: a key and the self-signed certificate that names it.
struct Party {
    key_der: Vec<u8>,
    certificate_der: Vec<u8>,
}

impl Party {
    fn new(which: Which, common_name: &str) -> Self {
        let key_der = key(which)
            .to_pkcs8_der()
            .expect("the generated key encodes as PKCS#8")
            .as_bytes()
            .to_vec();
        let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &key_der.clone().into(),
            &rcgen::PKCS_RSA_SHA256,
        )
        .expect("rcgen accepts the generated RSA key");
        let mut params =
            rcgen::CertificateParams::new(Vec::new()).expect("certificate parameters build");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        Self {
            certificate_der: params
                .self_signed(&pair)
                .expect("the certificate issues")
                .der()
                .to_vec(),
            key_der,
        }
    }

    fn recipient(&self) -> Recipient {
        Recipient::from_certificate(&self.certificate_der).expect("the certificate is usable")
    }

    fn decryption_key(&self) -> RecipientKey {
        RecipientKey::load(&self.key_der, None, Some(&self.certificate_der))
            .expect("the key and its certificate load")
    }
}

fn document(compress: bool) -> DocumentSpec {
    DocumentSpec {
        title: "secret.txt".to_owned(),
        media_type: None,
        bytes: PLAINTEXT.to_vec(),
        compress,
        encrypt: true,
    }
}

fn spec(documents: Vec<DocumentSpec>, encryption: Option<Encryption>) -> DossierSpec {
    DossierSpec {
        title: "Synthetic encrypted dossier".to_owned(),
        created: CREATED.to_owned(),
        documents,
        encryption,
    }
}

/// Build one dossier and read its first document back with `key`.
fn round_trip(
    documents: Vec<DocumentSpec>,
    encryption: Encryption,
    key: &RecipientKey,
) -> DecodeOutcome {
    let limits = Limits::default();
    let dossier = build(&spec(documents, Some(encryption)), &limits).expect("the dossier builds");
    let parsed = openszigno_core::parse(&dossier.bytes, &limits).expect("the dossier parses back");
    decode_document_with(
        &parsed,
        0,
        &limits,
        &DecryptOptions {
            key: Some(key),
            allow_legacy_ciphers: false,
        },
    )
    .expect("decoding does not fail")
}

fn plaintext(outcome: DecodeOutcome) -> Vec<u8> {
    match outcome {
        DecodeOutcome::Decoded(decoded) => {
            assert!(decoded.decrypted, "the document must be reported decrypted");
            decoded.bytes
        }
        DecodeOutcome::Unsupported(reason) => panic!("the document must decode: {reason:?}"),
    }
}

#[test]
fn the_default_transport_round_trips_plain_and_zipped_documents() {
    let party = Party::new(Which::Recipient, "openSzigno synthetic recipient");
    for compress in [false, true] {
        let encryption = Encryption {
            recipients: vec![party.recipient()],
            key_transport: KeyTransport::OaepSha256,
        };
        let outcome = round_trip(
            vec![document(compress)],
            encryption,
            &party.decryption_key(),
        );
        assert_eq!(plaintext(outcome), PLAINTEXT, "compress = {compress}");
    }
}

#[test]
fn the_legacy_transport_round_trips_through_the_same_reader() {
    let party = Party::new(Which::Recipient, "openSzigno synthetic recipient");
    let outcome = round_trip(
        vec![document(false)],
        Encryption {
            recipients: vec![party.recipient()],
            key_transport: KeyTransport::Pkcs1v15,
        },
        &party.decryption_key(),
    );
    assert_eq!(plaintext(outcome), PLAINTEXT);
}

#[test]
fn every_recipient_of_a_multi_recipient_document_can_read_it() {
    let first = Party::new(Which::Recipient, "openSzigno synthetic recipient");
    let second = Party::new(Which::Stranger, "openSzigno synthetic second");
    let encryption = || Encryption {
        recipients: vec![first.recipient(), second.recipient()],
        key_transport: KeyTransport::OaepSha256,
    };
    for key in [first.decryption_key(), second.decryption_key()] {
        let outcome = round_trip(vec![document(false)], encryption(), &key);
        assert_eq!(plaintext(outcome), PLAINTEXT);
    }
}

#[test]
fn a_document_addressed_to_somebody_else_is_skipped_not_failed() {
    let recipient = Party::new(Which::Recipient, "openSzigno synthetic recipient");
    let stranger = Party::new(Which::Stranger, "openSzigno synthetic stranger");
    let outcome = round_trip(
        vec![document(false)],
        Encryption {
            recipients: vec![recipient.recipient()],
            key_transport: KeyTransport::OaepSha256,
        },
        &stranger.decryption_key(),
    );
    assert!(
        matches!(
            outcome,
            DecodeOutcome::Unsupported(openszigno_core::UnsupportedReason::NoMatchingRecipient)
        ),
        "{outcome:?}"
    );
}

#[test]
fn encryption_makes_the_output_differ_between_runs() {
    let party = Party::new(Which::Recipient, "openSzigno synthetic recipient");
    let limits = Limits::default();
    let once = || {
        build(
            &spec(
                vec![document(false)],
                Some(Encryption {
                    recipients: vec![party.recipient()],
                    key_transport: KeyTransport::OaepSha256,
                }),
            ),
            &limits,
        )
        .expect("the dossier builds")
        .bytes
    };
    assert_ne!(
        once(),
        once(),
        "a fresh content key and IV per run is the point"
    );
    // Without recipients the determinism guarantee is unchanged.
    let plain = || {
        build(&spec(vec![document(false)], None), &limits)
            .expect("the dossier builds")
            .bytes
    };
    assert_eq!(plain(), plain());
}

#[test]
fn a_document_that_did_not_ask_for_encryption_is_written_in_the_clear() {
    let party = Party::new(Which::Recipient, "openSzigno synthetic recipient");
    let dossier = build(
        &spec(
            vec![DocumentSpec {
                encrypt: false,
                ..document(false)
            }],
            Some(Encryption {
                recipients: vec![party.recipient()],
                key_transport: KeyTransport::OaepSha256,
            }),
        ),
        &Limits::default(),
    )
    .expect("the dossier builds");
    assert_eq!(dossier.documents[0].transforms, ["base64"]);
    assert!(!dossier.documents[0].encrypted);
}

#[test]
fn a_certificate_that_is_not_usable_names_which_half_is_wrong() {
    let unreadable =
        Recipient::from_certificate(b"not a certificate").expect_err("this is not a certificate");
    assert_eq!(
        unreadable.code(),
        ErrorCode::InvalidRecipientCertificate,
        "{}",
        unreadable.message()
    );

    // An ECDSA certificate is a perfectly good certificate that this key
    // transport cannot address.
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("an ECDSA key generates");
    let params = rcgen::CertificateParams::new(vec!["ec.example".to_owned()])
        .expect("certificate parameters build");
    let certificate = params.self_signed(&pair).expect("the certificate issues");
    let error = Recipient::from_certificate(certificate.der()).expect_err("not an RSA key");
    assert_eq!(error.code(), ErrorCode::UnsupportedRecipientKey);
}

#[test]
fn the_declared_source_size_is_the_plaintext_length() {
    let party = Party::new(Which::Recipient, "openSzigno synthetic recipient");
    let dossier = build(
        &spec(
            vec![document(true)],
            Some(Encryption {
                recipients: vec![party.recipient()],
                key_transport: KeyTransport::OaepSha256,
            }),
        ),
        &Limits::default(),
    )
    .expect("the dossier builds");
    let built = &dossier.documents[0];
    assert_eq!(built.source_size, PLAINTEXT.len() as u64);
    assert!(built.encrypted);
    // The forward order the specification fixes, which the reader reverses.
    assert_eq!(built.transforms, ["zip", "encrypt", "base64"]);
}
