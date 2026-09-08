//! `create --encrypt-for`: the flags, the dossier it writes, the codes it
//! refuses with, and the guarantee that no key or content-key byte reaches
//! any output.
//!
//! Everything runs through the built binary, because the flags and the
//! envelope are the command contract rather than a library API. The recipient
//! keys and certificates come from the same run-time generator the decryption
//! tests use, so what `create` writes is decrypted here by exactly the code
//! path `extract --decrypt-key` exercises. No key material is committed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

#[path = "../../openszigno-core/tests/common/envelope.rs"]
mod envelope;
use envelope::{Recipient, Which};

const CREATED: &str = "2026-01-01T00:00:00Z";
const PLAINTEXT: &[u8] = b"A payload only a recipient's private key can read.\n";

fn scratch() -> TempDir {
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory must resolve");
    tempfile::tempdir_in(base).expect("a temporary directory must be available")
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(args)
        .output()
        .expect("CLI must run")
}

fn parse_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout must be exactly one JSON value")
}

fn path_of(path: &Path) -> String {
    path.to_str().expect("a UTF-8 path").to_owned()
}

/// Whether `haystack` holds `needle` anywhere. `windows` yields nothing when
/// the needle is longer than the haystack, so no length juggling is needed.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn warning_codes(value: &Value) -> Vec<String> {
    value["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|notice| notice["code"].as_str().map(str::to_owned))
        .collect()
}

/// A working directory holding one document and the material both sides need.
struct World {
    directory: TempDir,
    document: PathBuf,
    recipient: Recipient,
    stranger: Recipient,
}

impl World {
    fn new() -> Self {
        let directory = scratch();
        let document = directory.path().join("secret.txt");
        std::fs::write(&document, PLAINTEXT).expect("the input is written");
        Self {
            recipient: Recipient::new(Which::Recipient, "openSzigno synthetic recipient", true),
            stranger: Recipient::new(Which::Stranger, "openSzigno synthetic stranger", true),
            directory,
            document,
        }
    }

    fn at(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// Write `contents` under `name` and return the path.
    fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.at(name);
        std::fs::write(&path, contents).expect("the file is written");
        path
    }

    /// The recipient's certificate as PEM, and their key as PKCS#8 PEM.
    fn recipient_material(&self) -> (PathBuf, PathBuf) {
        (
            self.write("recipient.cert.pem", self.recipient.certificate_pem()),
            self.write("recipient.key.pem", self.recipient.key_pem()),
        )
    }

    fn stranger_material(&self) -> (PathBuf, PathBuf) {
        (
            self.write("stranger.cert.pem", self.stranger.certificate_pem()),
            self.write("stranger.key.pem", self.stranger.key_pem()),
        )
    }

    /// `create` one dossier from the single document, with `extra` appended.
    fn create(&self, output: &Path, extra: &[String]) -> Output {
        let mut args = vec![
            "create".to_owned(),
            "--output".to_owned(),
            path_of(output),
            "--title".to_owned(),
            "Synthetic encrypted dossier".to_owned(),
            "--document".to_owned(),
            path_of(&self.document),
            "--created".to_owned(),
            CREATED.to_owned(),
            "--json".to_owned(),
        ];
        args.extend_from_slice(extra);
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        run(&borrowed)
    }

    /// `extract` the dossier with a key and certificate, into a fresh
    /// directory named `into`.
    fn extract(&self, dossier: &Path, into: &str, key: &Path, certificate: &Path) -> Output {
        run(&[
            "extract",
            &path_of(dossier),
            "--output",
            &path_of(&self.at(into)),
            "--json",
            "--decrypt-key",
            &path_of(key),
            "--decrypt-cert",
            &path_of(certificate),
        ])
    }
}

/// Acceptance 1: a created dossier round trips byte for byte, plain and
/// zipped, and is reported as decrypted on the way back.
#[test]
fn what_create_encrypts_extract_decrypts_byte_for_byte() {
    let world = World::new();
    let (certificate, key) = world.recipient_material();

    for (name, extra) in [("plain", Vec::new()), ("zipped", vec!["--zip".to_owned()])] {
        let dossier = world.at(&format!("{name}.es3"));
        let created = world.create(
            &dossier,
            &[
                extra,
                vec!["--encrypt-for".to_owned(), path_of(&certificate)],
            ]
            .concat(),
        );
        assert_eq!(created.status.code(), Some(0), "create must succeed");
        let value = parse_json(&created);
        assert_eq!(
            value["data"]["documents"][0]["encrypted"],
            Value::Bool(true)
        );
        let expected: Value = match name {
            "zipped" => serde_json::json!(["zip", "encrypt", "base64"]),
            _ => serde_json::json!(["encrypt", "base64"]),
        };
        assert_eq!(value["data"]["documents"][0]["transforms"], expected);

        let extracted = world.extract(&dossier, &format!("{name}-out"), &key, &certificate);
        assert_eq!(extracted.status.code(), Some(0), "extract must succeed");
        let value = parse_json(&extracted);
        assert_eq!(value["data"]["extracted_count"], 1);
        assert_eq!(
            value["data"]["extracted"][0]["decrypted"],
            Value::Bool(true)
        );
        assert_eq!(
            std::fs::read(world.at(&format!("{name}-out")).join("secret.txt"))
                .expect("the document was written"),
            PLAINTEXT,
            "{name}"
        );
    }
}

/// Acceptance 2: every named recipient can read the document, and nobody else.
#[test]
fn each_recipient_reads_the_document_and_a_stranger_does_not() {
    let world = World::new();
    let (certificate, key) = world.recipient_material();
    let (stranger_certificate, stranger_key) = world.stranger_material();
    // The second recipient is given as DER, to cover both encodings.
    let second = world.write("second.cert.der", world.stranger.certificate_der.clone());
    let third = Recipient::new(Which::Stranger, "openSzigno synthetic outsider", false);

    let dossier = world.at("two.es3");
    let created = world.create(
        &dossier,
        &[
            "--encrypt-for".to_owned(),
            path_of(&certificate),
            "--encrypt-for".to_owned(),
            path_of(&second),
        ],
    );
    assert_eq!(created.status.code(), Some(0));

    for (index, (key, certificate)) in
        [(&key, &certificate), (&stranger_key, &stranger_certificate)]
            .into_iter()
            .enumerate()
    {
        let extracted = world.extract(&dossier, &format!("out{index}"), key, certificate);
        assert_eq!(extracted.status.code(), Some(0));
        let value = parse_json(&extracted);
        assert_eq!(value["data"]["extracted_count"], 1, "recipient {index}");
        assert_eq!(
            std::fs::read(world.at(&format!("out{index}")).join("secret.txt"))
                .expect("the document was written"),
            PLAINTEXT
        );
    }

    // A key whose certificate names none of the CMS recipients is a skip and
    // not a failure: a dossier may perfectly well hold documents for several
    // people. The outsider certificate is deliberately a second, differently
    // named certificate over an existing key, because matching is by
    // `issuerAndSerialNumber` and not by trial decryption.
    let outsider_certificate = world.write("outsider.cert.pem", third.certificate_pem());
    let outsider_key = world.write("outsider.key.pem", third.key_pem());
    let extracted = world.extract(
        &dossier,
        "outsider-out",
        &outsider_key,
        &outsider_certificate,
    );
    assert_eq!(extracted.status.code(), Some(0));
    let value = parse_json(&extracted);
    assert_eq!(value["data"]["skipped_count"], 1);
    assert!(
        warning_codes(&value).contains(&"document_skipped_no_matching_recipient".to_owned()),
        "{:?}",
        warning_codes(&value)
    );
}

/// Acceptance 3: the legacy key transport reaches the same reader.
#[test]
fn the_legacy_key_transport_round_trips_too() {
    let world = World::new();
    let (certificate, key) = world.recipient_material();
    let dossier = world.at("legacy.es3");
    let created = world.create(
        &dossier,
        &[
            "--encrypt-for".to_owned(),
            path_of(&certificate),
            "--legacy-key-transport".to_owned(),
        ],
    );
    assert_eq!(created.status.code(), Some(0));
    let extracted = world.extract(&dossier, "legacy-out", &key, &certificate);
    assert_eq!(extracted.status.code(), Some(0));
    assert_eq!(
        std::fs::read(world.at("legacy-out").join("secret.txt")).expect("the document was written"),
        PLAINTEXT
    );
    // The flag is meaningless without a recipient, and `clap` says so.
    let refused = run(&[
        "create",
        "--output",
        "x.es3",
        "--title",
        "T",
        "--legacy-key-transport",
    ]);
    assert_eq!(refused.status.code(), Some(2));
}

/// Acceptance 4: the other commands report the document exactly the way they
/// report the committed encrypted fixture.
#[test]
fn list_inspect_and_validate_structure_see_an_ordinary_encrypted_document() {
    let world = World::new();
    let (certificate, _) = world.recipient_material();
    let dossier = world.at("reported.es3");
    assert_eq!(
        world
            .create(
                &dossier,
                &["--encrypt-for".to_owned(), path_of(&certificate)]
            )
            .status
            .code(),
        Some(0)
    );

    let listed = run(&["list", &path_of(&dossier), "--json"]);
    assert_eq!(listed.status.code(), Some(0));
    let value = parse_json(&listed);
    assert_eq!(
        value["data"]["documents"][0]["transforms"],
        serde_json::json!(["encrypt", "base64"])
    );
    assert_eq!(
        warning_codes(&value),
        ["encrypted_document_unsupported".to_owned()]
    );

    let inspected = run(&["inspect", &path_of(&dossier), "--json"]);
    assert_eq!(inspected.status.code(), Some(0));
    let value = parse_json(&inspected);
    assert_eq!(
        value["data"]["capabilities"]["encrypted_extraction"],
        Value::String("with_key".to_owned())
    );
    assert_eq!(
        warning_codes(&value),
        ["encrypted_document_unsupported".to_owned()]
    );

    let validated = run(&["validate-structure", &path_of(&dossier), "--json"]);
    assert_eq!(validated.status.code(), Some(0));
    let value = parse_json(&validated);
    assert_eq!(value["data"]["valid_structure"], Value::Bool(true));
    assert_eq!(value["data"]["conformance_warnings"], 0);
}

/// Acceptance 5: an unusable recipient certificate is refused with a stable
/// code at exit 4, and an expired one is a warning rather than a refusal.
#[test]
fn an_unusable_recipient_certificate_is_refused_before_anything_is_written() {
    let world = World::new();
    let output = world.at("never.es3");

    for (name, contents) in [
        ("garbage.pem", b"not a certificate".to_vec()),
        ("empty.pem", Vec::new()),
        (
            "truncated.der",
            world.recipient.certificate_der[..8].to_vec(),
        ),
    ] {
        let certificate = world.write(name, contents);
        let created = world.create(
            &output,
            &["--encrypt-for".to_owned(), path_of(&certificate)],
        );
        assert_eq!(created.status.code(), Some(4), "{name}");
        let value = parse_json(&created);
        assert_eq!(
            value["errors"][0]["code"],
            Value::String("invalid_recipient_certificate".to_owned()),
            "{name}"
        );
        assert!(!output.exists(), "nothing is written for {name}");
    }

    // A certificate whose key is not RSA is a different answer: the file is
    // fine, the key transport cannot address it.
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("an ECDSA key");
    let ecdsa = rcgen::CertificateParams::new(vec!["ec.example".to_owned()])
        .expect("certificate parameters build")
        .self_signed(&pair)
        .expect("the certificate issues");
    let certificate = world.write("ec.der", ecdsa.der());
    let created = world.create(
        &output,
        &["--encrypt-for".to_owned(), path_of(&certificate)],
    );
    assert_eq!(created.status.code(), Some(4));
    assert_eq!(
        parse_json(&created)["errors"][0]["code"],
        Value::String("unsupported_recipient_key".to_owned())
    );

    // A missing file is an I/O error, as it is for `--document`.
    let created = world.create(
        &output,
        &[
            "--encrypt-for".to_owned(),
            "/nonexistent/openszigno/recipient.pem".to_owned(),
        ],
    );
    assert_eq!(created.status.code(), Some(3));
    assert_eq!(
        parse_json(&created)["errors"][0]["code"],
        Value::String("io_error".to_owned())
    );
}

/// A self-signed certificate for `recipient`'s key that stopped being valid
/// in the past, as PEM. Issued here rather than in the shared generator
/// because expiry is a `create` concern only.
fn expired_certificate_pem(recipient: &Recipient) -> String {
    let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &recipient.private_pkcs8_der.clone().into(),
        &rcgen::PKCS_RSA_SHA256,
    )
    .expect("rcgen accepts the generated RSA key");
    let mut params =
        rcgen::CertificateParams::new(Vec::new()).expect("certificate parameters build");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "openSzigno expired recipient");
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    let certificate = params.self_signed(&pair).expect("the certificate issues");
    envelope::pem_block("CERTIFICATE", certificate.der())
}

/// An expired recipient certificate is written for, with a warning: nothing
/// in the format or in the reader consults its validity.
#[test]
fn an_expired_recipient_certificate_is_a_warning_and_still_round_trips() {
    let world = World::new();
    let expired = world.write("expired.pem", expired_certificate_pem(&world.recipient));
    let key = world.write("expired.key.pem", world.recipient.key_pem());
    let dossier = world.at("expired.es3");

    let created = world.create(&dossier, &["--encrypt-for".to_owned(), path_of(&expired)]);
    assert_eq!(created.status.code(), Some(0), "expiry is not a refusal");
    let value = parse_json(&created);
    assert!(
        warning_codes(&value).contains(&"recipient_certificate_expired".to_owned()),
        "{:?}",
        warning_codes(&value)
    );
    // The last warning stays the one every `create` run emits.
    assert_eq!(
        warning_codes(&value).last().map(String::as_str),
        Some("created_dossier_unsigned")
    );

    let extracted = world.extract(&dossier, "expired-out", &key, &expired);
    assert_eq!(extracted.status.code(), Some(0));
    assert_eq!(
        std::fs::read(world.at("expired-out").join("secret.txt"))
            .expect("the document was written"),
        PLAINTEXT
    );
}

/// Acceptance 6: nothing secret reaches stdout, stderr, or the envelope.
///
/// The content-encryption key never leaves the process at all, so what can be
/// checked from outside is that the recipient's private key, in any of the
/// encodings it exists in, appears nowhere in either stream, on a run that
/// succeeds and on one that fails.
#[test]
fn no_key_material_reaches_any_output() {
    let world = World::new();
    let (certificate, _) = world.recipient_material();
    let secrets: Vec<Vec<u8>> = vec![
        world.recipient.private_pkcs8_der.clone(),
        world.recipient.key_pem().into_bytes(),
        // The Base64 body on its own, in case an encoding stripped the armour.
        world
            .recipient
            .key_pem()
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>()
            .into_bytes(),
    ];

    let mut outputs = vec![world.create(
        &world.at("secretive.es3"),
        &["--encrypt-for".to_owned(), path_of(&certificate)],
    )];
    // The same over a failing run, whose message names a recipient.
    let broken = world.write("broken.pem", b"not a certificate");
    outputs.push(world.create(
        &world.at("unwritten.es3"),
        &["--encrypt-for".to_owned(), path_of(&broken)],
    ));

    for output in &outputs {
        for stream in [&output.stdout, &output.stderr] {
            for secret in &secrets {
                assert!(
                    !contains(stream, secret),
                    "key material must never appear in any output stream"
                );
            }
        }
    }
}
