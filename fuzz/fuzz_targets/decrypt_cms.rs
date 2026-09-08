//! Fuzz the CMS `encrypt` transform decrypt path
//! (`openszigno_core::decrypt`) through the public `decode_document_with`
//! entry point, with a synthetic RSA recipient key and self-signed
//! certificate generated at run time.
//!
//! **No private key, in any encoding, is committed here.** This mirrors
//! `crates/openszigno-core/tests/common/envelope.rs` exactly: the key comes
//! from a fixed seed through `ChaCha20Rng`, generated once per process behind
//! a `LazyLock`, so the target stays deterministic without a scanner-visible
//! key ever touching the tree. See `SECURITY.md` for why: "a secret scanner
//! cannot tell a synthetic key from a real one, and this project does not
//! allowlist scanner rules, so the only safe amount of key material in the
//! tree is none."

#![no_main]

use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use libfuzzer_sys::fuzz_target;
use openszigno_core::{DecryptOptions, Limits, RecipientKey, decode_document_with, parse};
use rand_core::SeedableRng as _;
use rsa::pkcs8::EncodePrivateKey as _;

/// Any fixed value would do; this one is arbitrary, chosen only so the key
/// this target generates is stable across runs.
const SEED: u64 = 0x4675_7A7A_4553_3300;

fn recipient_key() -> &'static RecipientKey {
    static KEY: LazyLock<RecipientKey> = LazyLock::new(|| {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(SEED);
        let private =
            rsa::RsaPrivateKey::new(&mut rng, 2048).expect("a synthetic RSA key generates");
        let pkcs8_der = private
            .to_pkcs8_der()
            .expect("the synthetic RSA key encodes to PKCS#8")
            .as_bytes()
            .to_vec();

        let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &pkcs8_der.clone().into(),
            &rcgen::PKCS_RSA_SHA256,
        )
        .expect("the synthetic key loads into rcgen");
        let mut params = rcgen::CertificateParams::new(vec!["fuzz.openszigno.invalid".to_owned()])
            .expect("certificate parameters build");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "openSzigno fuzz recipient");
        let certificate = params
            .self_signed(&key_pair)
            .expect("the synthetic certificate self-signs");
        let cert_der = certificate.der().to_vec();

        RecipientKey::load(&pkcs8_der, None, Some(&cert_der))
            .expect("the synthetic key and certificate load and match")
    });
    &KEY
}

fn dossier_xml(payload_base64: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:DossierProfile Id="DossierProfile1" OBJREF="Object0">
    <es:Title>fuzz</es:Title>
    <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>
  </es:DossierProfile>
  <es:Documents Id="Object0">
    <es:Document>
      <es:DocumentProfile Id="DocumentProfile1" OBJREF="DocumentObject1">
        <es:Title>fuzz.bin</es:Title>
        <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="application" subtype="octet-stream"/></es:Format>
        <es:BaseTransform><es:Transform Algorithm="encrypt"/><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="DocumentObject1">{payload_base64}</ds:Object>
    </es:Document>
  </es:Documents>
</es:Dossier>"#
    )
}

fuzz_target!(|data: &[u8]| {
    // The fuzzed bytes become the DER `ContentInfo` the CMS decryptor parses;
    // base64-encoding them first (rather than embedding them as text)
    // guarantees the Base64 stage always succeeds, so every run actually
    // reaches `decrypt_cms` instead of bailing out at the encoding it does
    // not exist to test (that path is `decode_payload`'s job).
    if data.len() > 256 * 1024 {
        return;
    }
    let payload_base64 = STANDARD.encode(data);
    let xml = dossier_xml(&payload_base64);

    let limits = Limits::default();
    let Ok(dossier) = parse(xml.as_bytes(), &limits) else {
        return;
    };
    if dossier.documents.is_empty() {
        return;
    }
    let options = DecryptOptions {
        key: Some(recipient_key()),
        allow_legacy_ciphers: data.first().is_some_and(|byte| byte & 1 == 1),
    };
    let _ = decode_document_with(&dossier, 0, &limits, &options);
});
