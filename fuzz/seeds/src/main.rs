//! Regenerates `fuzz/corpus/<target>/*` deterministically.
//!
//! Run with `fuzz/seed.sh` (which also copies a few public fixtures) or
//! directly with `cargo run --manifest-path fuzz/seeds/Cargo.toml`. Every
//! seed here is either copied from the repository's own public
//! `tests/fixtures`, or built in-process from hand-built synthetic bytes,
//! including a synthetic RSA certificate generated at run time (see
//! `synthetic_certificate` below) from the same fixed seed
//! `fuzz/fuzz_targets/decrypt_cms.rs` uses — **no private key is committed
//! here**; see that file's doc comment and `SECURITY.md`. Nothing here reads
//! `samples/` or any private corpus.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use der::asn1::BitString;
use der::{Any, Decode, Encode};
use rand_core::SeedableRng as _;
use rsa::pkcs8::EncodePrivateKey as _;

/// Same fixed seed as `fuzz/fuzz_targets/decrypt_cms.rs`; any fixed value
/// would do. Only used here to mint a *certificate* (public by nature) for
/// seed corpora, never to decrypt anything.
const SEED: u64 = 0x4675_7A7A_4553_3300;

/// A synthetic self-signed certificate, generated once per process from the
/// fixed seed above. The private key backing it is never written to disk or
/// returned from this function.
fn synthetic_certificate() -> &'static [u8] {
    static CERT_DER: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(SEED);
        let private =
            rsa::RsaPrivateKey::new(&mut rng, 2048).expect("a synthetic RSA key generates");
        let pkcs8_der = private
            .to_pkcs8_der()
            .expect("the synthetic RSA key encodes to PKCS#8")
            .as_bytes()
            .to_vec();

        let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &pkcs8_der.into(),
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
        certificate.der().to_vec()
    });
    &CERT_DER
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).expect("create corpus directory");
    fs::write(dir.join(name), bytes).expect("write corpus seed");
}

fn corpus_root() -> PathBuf {
    // `cargo run --manifest-path fuzz/seeds/Cargo.toml` sets CARGO_MANIFEST_DIR
    // to `fuzz/seeds`; the corpus lives one level up, at `fuzz/corpus`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("fuzz/seeds has a parent directory")
        .join("corpus")
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("fuzz/seeds/../.. is the repository root")
        .join("tests/fixtures")
}

/// Copy a handful of small public `.es3` fixtures into `parse_dossier`,
/// `sniff`, and `decode_payload`'s corpora. These are already committed,
/// public, and small (see `tests/fixtures/README.md`); nothing here is a
/// private or real-world dossier.
fn seed_dossier_fixtures(root: &Path) {
    let fixtures = fixtures_root();
    let names = [
        "plain-base64.es3",
        "zip-base64.es3",
        "encrypted.es3",
        "two-documents.es3",
        "duplicate-id.es3",
        "nested-dossier.es3",
        "unresolved-objref.es3",
        "invalid-base64.es3",
        "compatible-namespace.es3",
        "doctype.es3",
        "traversal-title.es3",
    ];
    let parse_dir = root.join("parse_dossier");
    let sniff_dir = root.join("sniff");
    for name in names {
        let path = fixtures.join(name);
        let Ok(bytes) = fs::read(&path) else {
            eprintln!("skipping missing fixture {path:?}");
            continue;
        };
        write(&parse_dir, name, &bytes);
        write(&sniff_dir, name, &bytes);
    }
    // A few non-dossier shapes for `sniff` to classify.
    write(&sniff_dir, "empty", b"");
    write(&sniff_dir, "not-xml.txt", b"this is not a dossier at all");
    write(
        &sniff_dir,
        "pdf-header.bin",
        b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< >>\nendobj\n",
    );
    write(
        &sniff_dir,
        "unrelated-xml.xml",
        b"<?xml version=\"1.0\"?><root xmlns=\"urn:example\"><child/></root>",
    );
}

fn seed_decode_payload(root: &Path) {
    let dir = root.join("decode_payload");
    // Selector byte 0 => base64 transform; the rest is the raw (usually
    // invalid) "Base64" text embedded verbatim.
    write(&dir, "base64-ascii", b"\x00SGVsbG8gd29ybGQh");
    write(&dir, "base64-garbage", b"\x00not base64 at all!!");
    write(&dir, "base64-empty", b"\x00");
    // Selector byte 1 => zip+base64 transform; the rest, base64-encoded by
    // the harness, becomes the "ZIP archive" bytes `decode_zip` receives.
    write(&dir, "zip-garbage", b"\x01PK\x03\x04not a real zip");
    write(&dir, "zip-empty", b"\x01");
    let mut zip_magic_only = vec![1u8];
    zip_magic_only.extend_from_slice(
        b"PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    );
    write(&dir, "zip-empty-central-directory", &zip_magic_only);
}

fn seed_c14n(root: &Path) {
    let dir = root.join("c14n");
    let samples: [(&str, &[u8]); 6] = [
        (
            "simple.xml",
            b"<?xml version=\"1.0\"?><a><b/><c x=\"1\" y=\"2\"/></a>",
        ),
        (
            "namespaces.xml",
            b"<a xmlns=\"urn:x\" xmlns:p=\"urn:y\"><p:b/><b/></a>",
        ),
        (
            "comments-and-pi.xml",
            b"<?xml version=\"1.0\"?><!-- top --><a><!-- inner --><?pi data?></a>",
        ),
        (
            "xml-lang-base.xml",
            b"<a xml:lang=\"en\" xml:base=\"http://example/\"><b xml:lang=\"hu\"/></a>",
        ),
        (
            "attribute-order.xml",
            b"<a z=\"1\" a=\"2\" m=\"3\"><b/></a>",
        ),
        ("empty-elements.xml", b"<a><b></b><c/><d>   </d></a>"),
    ];
    for (name, bytes) in samples {
        write(&dir, name, bytes);
    }
}

fn seed_crl(root: &Path) {
    use x509_cert::Certificate;
    use x509_cert::crl::{CertificateList, TbsCertList};
    use x509_cert::serial_number::SerialNumber;

    let dir = root.join("crl_parse");
    write(&dir, "empty", b"");
    write(&dir, "not-der", b"this is not a CRL");

    let cert_der = synthetic_certificate();
    let certificate = Certificate::from_der(cert_der).expect("synthetic fuzz certificate parses");
    let tbs = TbsCertList {
        version: x509_cert::Version::V2,
        signature: certificate.signature_algorithm.clone(),
        issuer: certificate.tbs_certificate.issuer.clone(),
        this_update: certificate.tbs_certificate.validity.not_before,
        next_update: Some(certificate.tbs_certificate.validity.not_after),
        revoked_certificates: None,
        crl_extensions: None,
    };
    let empty_crl = CertificateList {
        tbs_cert_list: tbs.clone(),
        signature_algorithm: certificate.signature_algorithm.clone(),
        // Structurally valid, cryptographically meaningless: a fuzz seed
        // needs to parse as a `CertificateList`, not verify as one.
        signature: BitString::from_bytes(&[0u8; 256]).expect("bit string"),
    };
    write(
        &dir,
        "empty-crl.der",
        &empty_crl.to_der().expect("encode CertificateList"),
    );

    let revoked = x509_cert::crl::RevokedCert {
        serial_number: SerialNumber::new(&[0x01, 0x02, 0x03]).expect("serial"),
        revocation_date: certificate.tbs_certificate.validity.not_before,
        crl_entry_extensions: None,
    };
    let mut tbs_with_entry = tbs;
    tbs_with_entry.revoked_certificates = Some(vec![revoked]);
    let crl_with_entry = CertificateList {
        tbs_cert_list: tbs_with_entry,
        signature_algorithm: certificate.signature_algorithm.clone(),
        signature: BitString::from_bytes(&[0u8; 256]).expect("bit string"),
    };
    write(
        &dir,
        "one-entry-crl.der",
        &crl_with_entry.to_der().expect("encode CertificateList"),
    );
}

fn seed_ocsp(root: &Path) {
    use x509_ocsp::OcspResponse;

    let dir = root.join("ocsp_parse");
    write(&dir, "empty", b"");
    write(&dir, "not-der", b"this is not an OCSP response");

    let variants: [(&str, OcspResponse); 5] = [
        ("malformed-request.der", OcspResponse::malformed_request()),
        ("internal-error.der", OcspResponse::internal_error()),
        ("try-later.der", OcspResponse::try_later()),
        ("sig-required.der", OcspResponse::sig_required()),
        ("unauthorized.der", OcspResponse::unauthorized()),
    ];
    for (name, response) in variants {
        write(&dir, name, &response.to_der().expect("encode OcspResponse"));
    }
}

fn seed_tsa_token(root: &Path) {
    use cms::content_info::ContentInfo;
    use const_oid::ObjectIdentifier;

    let dir = root.join("tsa_token");
    write(&dir, "empty", b"");
    write(&dir, "not-der", b"this is not a timestamp token");

    // A syntactically valid `ContentInfo` whose content is an empty
    // OCTET STRING rather than a real `SignedData`: enough to reach and
    // then fail `token_certificates`'s inner `SignedData::from_der`, which
    // is exactly the boundary this target exists to exercise.
    let content_type: ObjectIdentifier = "1.2.840.113549.1.7.2".parse().expect("signedData OID");
    let content = Any::encode_from(&der::asn1::OctetString::new(Vec::new()).expect("octet string"))
        .expect("encode inner Any");
    let info = ContentInfo {
        content_type,
        content,
    };
    write(
        &dir,
        "content-info-empty-content.der",
        &info.to_der().expect("encode ContentInfo"),
    );
}

fn seed_trustlist(root: &Path) {
    let dir = root.join("trustlist_parse");
    write(&dir, "empty", b"");
    write(&dir, "not-xml", b"this is not a trusted list");
    write(
        &dir,
        "minimal-tsl.xml",
        br#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <SchemeTerritory>HU</SchemeTerritory>
  </SchemeInformation>
  <TrustServiceProviderList>
  </TrustServiceProviderList>
</TrustServiceStatusList>"#,
    );
    write(
        &dir,
        "wrong-root.xml",
        b"<?xml version=\"1.0\"?><NotATrustList xmlns=\"http://uri.etsi.org/02231/v2#\"/>",
    );
}

fn seed_certificate(root: &Path) {
    let dir = root.join("certificate_parse");
    write(&dir, "empty", b"");
    write(&dir, "not-a-certificate", b"definitely not a certificate");

    let cert_der = synthetic_certificate();
    write(&dir, "synthetic-recipient.der", cert_der);

    let pem_body = pem_wrap("CERTIFICATE", cert_der);
    write(&dir, "synthetic-recipient.pem", pem_body.as_bytes());

    // Two PEM blocks back to back, which `certificates_from_bytes` is
    // documented to accept as two certificates.
    let doubled = format!("{pem_body}{pem_body}");
    write(&dir, "synthetic-recipient-doubled.pem", doubled.as_bytes());
}

fn pem_wrap(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn seed_decrypt_cms(root: &Path) {
    let dir = root.join("decrypt_cms");
    write(&dir, "empty", b"");
    write(&dir, "not-der", b"this is not a CMS ContentInfo");
}

fn main() {
    let root = corpus_root();
    seed_dossier_fixtures(&root);
    seed_decode_payload(&root);
    seed_decrypt_cms(&root);
    seed_c14n(&root);
    seed_crl(&root);
    seed_ocsp(&root);
    seed_tsa_token(&root);
    seed_trustlist(&root);
    seed_certificate(&root);
    println!("wrote seed corpus under {}", root.display());
}
