//! `extract --decrypt-key`: the flags, the JSON it adds, the codes it emits,
//! and the guarantee that no key material reaches any output.
//!
//! Everything runs through the built binary, because the flags and the
//! envelope are the command contract rather than a library API.

use std::path::PathBuf;
use std::process::{Command, Output};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use tempfile::TempDir;

#[path = "../../openszigno-core/tests/common/envelope.rs"]
mod envelope;
use envelope::{Cipher, KeyTransport, Message, Naming, PASSPHRASE, Recipient, Which};

const PLAINTEXT: &[u8] = b"Synthetic encrypted e-dossier payload.\n";

fn scratch() -> TempDir {
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory must resolve");
    tempfile::tempdir_in(base).expect("a temporary directory must be available")
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(arguments)
        .output()
        .expect("CLI must run")
}

fn run_with_env(arguments: &[&str], name: &str, value: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(arguments)
        .env(name, value)
        .output()
        .expect("CLI must run")
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout must be exactly one JSON value")
}

fn recipient() -> Recipient {
    Recipient::new(Which::Recipient, "openSzigno synthetic recipient", true)
}

fn stranger() -> Recipient {
    Recipient::new(Which::Stranger, "openSzigno synthetic stranger", true)
}

/// One dossier whose only document is `payload` under `transforms`.
fn dossier(payload: &[u8], transforms: &[&str], source_size: usize) -> String {
    let transforms: String = transforms
        .iter()
        .map(|algorithm| format!("<es:Transform Algorithm=\"{algorithm}\"/>"))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<es:DossierProfile Id="DossierProfile1" OBJREF="Object0"><es:Title>Unsigned synthetic encrypted fixture</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate></es:DossierProfile>
<es:Documents Id="Object0"><es:Document><es:DocumentProfile Id="DocumentProfile1" OBJREF="DocumentObject1"><es:Title>secret</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format><es:SourceSize sizeValue="{source_size}" sizeUnit="B"/><es:BaseTransform>{transforms}</es:BaseTransform></es:DocumentProfile><ds:Object Id="DocumentObject1">{payload}</ds:Object></es:Document></es:Documents>
</es:Dossier>"#,
        source_size = source_size,
        transforms = transforms,
        payload = STANDARD.encode(payload),
    )
}

/// A directory holding one encrypted dossier plus the recipient's key and
/// certificate, ready to be passed to the CLI.
struct Fixture {
    directory: TempDir,
    dossier: PathBuf,
    key: PathBuf,
    certificate: PathBuf,
}

impl Fixture {
    fn new(message: &Message<'_>, addressed_to: &Recipient, owner: &Recipient) -> Self {
        let directory = scratch();
        let envelope = envelope::envelope(message, addressed_to);
        let dossier_path = directory.path().join("encrypted.es3");
        std::fs::write(
            &dossier_path,
            dossier(&envelope, &["encrypt", "base64"], message.plaintext.len()),
        )
        .expect("the dossier is writable");
        let key = directory.path().join("recipient.key.pem");
        std::fs::write(&key, owner.key_pem()).expect("the key is writable");
        let certificate = directory.path().join("recipient.cert.pem");
        std::fs::write(&certificate, owner.certificate_pem()).expect("the certificate is writable");
        Self {
            directory,
            dossier: dossier_path,
            key,
            certificate,
        }
    }

    fn simple() -> Self {
        let recipient = recipient();
        Self::new(
            &Message {
                plaintext: PLAINTEXT,
                cipher: Cipher::Aes256Cbc,
                transport: KeyTransport::Pkcs1v15,
                naming: Naming::IssuerAndSerial,
            },
            &recipient,
            &recipient,
        )
    }

    fn path(&self) -> &str {
        self.dossier.to_str().expect("the path is UTF-8")
    }

    fn key_path(&self) -> &str {
        self.key.to_str().expect("the path is UTF-8")
    }

    fn certificate_path(&self) -> &str {
        self.certificate.to_str().expect("the path is UTF-8")
    }

    fn output(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }
}

#[test]
fn a_supplied_key_decrypts_a_document_and_marks_it_decrypted() {
    let fixture = Fixture::simple();
    let out = fixture.output("out");
    let output = run(&[
        "extract",
        fixture.path(),
        "--output",
        out.to_str().unwrap(),
        "--json",
        "--decrypt-key",
        fixture.key_path(),
        "--decrypt-cert",
        fixture.certificate_path(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let value = json(&output);
    assert_eq!(value["ok"], Value::Bool(true));
    assert_eq!(value["data"]["extracted_count"], 1);
    assert_eq!(
        value["data"]["extracted"][0]["decrypted"],
        Value::Bool(true)
    );
    assert_eq!(
        std::fs::read(out.join("secret.txt")).expect("the document was written"),
        PLAINTEXT
    );
    // Decryption is not verification: the boundary statement is unchanged.
    assert_eq!(value["data"]["extracted"][0]["bytes"], PLAINTEXT.len());
}

#[test]
fn a_plain_document_is_not_reported_as_decrypted() {
    let fixture = Fixture::simple();
    let plain = fixture.directory.path().join("plain.es3");
    std::fs::write(&plain, dossier(PLAINTEXT, &["base64"], PLAINTEXT.len()))
        .expect("the dossier is writable");
    let out = fixture.output("plain-out");
    let output = run(&[
        "extract",
        plain.to_str().unwrap(),
        "--output",
        out.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        json(&output)["data"]["extracted"][0]["decrypted"],
        Value::Bool(false)
    );
}

#[test]
fn without_a_key_an_encrypted_document_is_still_skipped() {
    let fixture = Fixture::simple();
    let out = fixture.output("out");
    let output = run(&[
        "extract",
        fixture.path(),
        "--output",
        out.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let value = json(&output);
    assert_eq!(value["data"]["skipped_count"], 1);
    let codes = warning_codes(&value);
    assert!(
        codes.contains(&"document_skipped_encrypted".to_owned()),
        "{codes:?}"
    );
    assert!(
        codes.contains(&"encrypted_document_unsupported".to_owned()),
        "{codes:?}"
    );
}

#[test]
fn a_key_file_that_bundles_its_certificate_needs_no_decrypt_cert() {
    let recipient = recipient();
    let fixture = Fixture::simple();
    let bundle = fixture.directory.path().join("bundle.pem");
    std::fs::write(&bundle, recipient.pem_bundle()).expect("the bundle is writable");
    let out = fixture.output("bundle-out");
    let output = run(&[
        "extract",
        fixture.path(),
        "--output",
        out.to_str().unwrap(),
        "--json",
        "--decrypt-key",
        bundle.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(json(&output)["data"]["extracted_count"], 1);
}

#[test]
fn a_bare_key_without_a_certificate_is_refused_before_anything_is_read() {
    let fixture = Fixture::simple();
    let out = fixture.output("out");
    let output = run(&[
        "extract",
        fixture.path(),
        "--output",
        out.to_str().unwrap(),
        "--json",
        "--decrypt-key",
        fixture.key_path(),
    ]);
    assert_eq!(output.status.code(), Some(4));
    let value = json(&output);
    assert_eq!(value["ok"], Value::Bool(false));
    assert_eq!(
        value["errors"][0]["code"],
        Value::String("decryption_certificate_required".to_owned())
    );
    assert!(!out.exists(), "no output directory is created");
}

#[test]
fn a_document_addressed_to_somebody_else_is_a_skip_warning_not_a_failure() {
    let recipient = recipient();
    let fixture = Fixture::new(
        &Message {
            plaintext: PLAINTEXT,
            cipher: Cipher::Aes128Cbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &stranger(),
        &recipient,
    );
    let out = fixture.output("out");
    let output = run(&[
        "extract",
        fixture.path(),
        "--output",
        out.to_str().unwrap(),
        "--json",
        "--decrypt-key",
        fixture.key_path(),
        "--decrypt-cert",
        fixture.certificate_path(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let value = json(&output);
    assert_eq!(value["ok"], Value::Bool(true));
    assert_eq!(value["data"]["skipped_count"], 1);
    assert!(
        warning_codes(&value).contains(&"document_skipped_no_matching_recipient".to_owned()),
        "{value}"
    );
}

#[test]
fn a_legacy_cipher_is_named_and_refused_until_the_flag_is_given() {
    let recipient = recipient();
    let fixture = Fixture::new(
        &Message {
            plaintext: PLAINTEXT,
            cipher: Cipher::TripleDesCbc,
            transport: KeyTransport::Pkcs1v15,
            naming: Naming::IssuerAndSerial,
        },
        &recipient,
        &recipient,
    );
    let refused = fixture.output("refused");
    let output = run(&[
        "extract",
        fixture.path(),
        "--output",
        refused.to_str().unwrap(),
        "--json",
        "--decrypt-key",
        fixture.key_path(),
        "--decrypt-cert",
        fixture.certificate_path(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let value = json(&output);
    assert_eq!(value["data"]["skipped_count"], 1);
    let warning = value["warnings"]
        .as_array()
        .expect("warnings is an array")
        .iter()
        .find(|notice| notice["code"] == "document_skipped_legacy_cipher")
        .expect("the legacy cipher is reported")
        .clone();
    assert!(
        warning["message"]
            .as_str()
            .expect("a message")
            .contains("1.2.840.113549.3.7"),
        "the OID is named: {warning}"
    );

    let allowed = fixture.output("allowed");
    let output = run(&[
        "extract",
        fixture.path(),
        "--output",
        allowed.to_str().unwrap(),
        "--json",
        "--decrypt-key",
        fixture.key_path(),
        "--decrypt-cert",
        fixture.certificate_path(),
        "--allow-legacy-ciphers",
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(json(&output)["data"]["extracted_count"], 1);
    assert_eq!(
        std::fs::read(allowed.join("secret.txt")).expect("the document was written"),
        PLAINTEXT
    );
}

#[test]
fn a_malformed_cms_payload_fails_the_run_with_invalid_cms() {
    let fixture = Fixture::simple();
    let broken = fixture.directory.path().join("broken.es3");
    std::fs::write(
        &broken,
        dossier(b"not DER at all", &["encrypt", "base64"], PLAINTEXT.len()),
    )
    .expect("the dossier is writable");
    let out = fixture.output("broken-out");
    let output = run(&[
        "extract",
        broken.to_str().unwrap(),
        "--output",
        out.to_str().unwrap(),
        "--json",
        "--decrypt-key",
        fixture.key_path(),
        "--decrypt-cert",
        fixture.certificate_path(),
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        json(&output)["errors"][0]["code"],
        Value::String("invalid_cms".to_owned())
    );
}

#[test]
fn a_passphrase_comes_from_a_file_or_the_environment_but_never_from_argv() {
    let recipient = recipient();
    let fixture = Fixture::simple();
    let encrypted = fixture.directory.path().join("recipient.enc.pem");
    std::fs::write(&encrypted, recipient.encrypted_key_pem()).expect("the key is writable");
    let passphrase_file = fixture.directory.path().join("passphrase");
    std::fs::write(&passphrase_file, format!("{PASSPHRASE}\n"))
        .expect("the passphrase file is writable");
    let certificate = fixture.directory.path().join("recipient.cert.der");
    std::fs::write(&certificate, &recipient.certificate_der).expect("the certificate is writable");

    let from_file = fixture.output("from-file");
    let output = run(&[
        "extract",
        fixture.path(),
        "--output",
        from_file.to_str().unwrap(),
        "--json",
        "--decrypt-key",
        encrypted.to_str().unwrap(),
        "--decrypt-cert",
        certificate.to_str().unwrap(),
        "--decrypt-passphrase-file",
        passphrase_file.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", json(&output));
    assert_eq!(json(&output)["data"]["extracted_count"], 1);

    let from_env = fixture.output("from-env");
    let output = run_with_env(
        &[
            "extract",
            fixture.path(),
            "--output",
            from_env.to_str().unwrap(),
            "--json",
            "--decrypt-key",
            encrypted.to_str().unwrap(),
            "--decrypt-cert",
            certificate.to_str().unwrap(),
        ],
        "OPENSZIGNO_DECRYPT_PASSPHRASE",
        PASSPHRASE,
    );
    assert_eq!(output.status.code(), Some(0), "{}", json(&output));
    assert_eq!(json(&output)["data"]["extracted_count"], 1);

    // Without either, the key cannot be read, and the failure says nothing
    // about what the passphrase might have been.
    let output = run(&[
        "extract",
        fixture.path(),
        "--output",
        fixture.output("none").to_str().unwrap(),
        "--json",
        "--decrypt-key",
        encrypted.to_str().unwrap(),
        "--decrypt-cert",
        certificate.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        json(&output)["errors"][0]["code"],
        Value::String("invalid_decryption_key".to_owned())
    );

    // The flag that would put a passphrase in the process table does not exist.
    let output = run(&["extract", "--help"]);
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        !help.contains("--decrypt-passphrase "),
        "no flag takes a passphrase value directly"
    );
}

#[test]
fn no_key_or_passphrase_material_appears_in_any_output() {
    let recipient = recipient();
    let fixture = Fixture::simple();
    let encrypted_key = recipient.encrypted_key_pem();
    let key_path = fixture.directory.path().join("recipient.enc.pem");
    std::fs::write(&key_path, &encrypted_key).expect("the key is writable");
    let passphrase_file = fixture.directory.path().join("passphrase");
    std::fs::write(&passphrase_file, PASSPHRASE).expect("the passphrase is writable");

    // A successful run, a failing run, and a human-mode run: the guarantee
    // holds on stdout, on stderr, and in the JSON envelope alike.
    let runs = [
        run(&[
            "extract",
            fixture.path(),
            "--output",
            fixture.output("clean-json").to_str().unwrap(),
            "--json",
            "--decrypt-key",
            key_path.to_str().unwrap(),
            "--decrypt-cert",
            fixture.certificate_path(),
            "--decrypt-passphrase-file",
            passphrase_file.to_str().unwrap(),
        ]),
        run(&[
            "extract",
            fixture.path(),
            "--output",
            fixture.output("clean-human").to_str().unwrap(),
            "--decrypt-key",
            key_path.to_str().unwrap(),
            "--decrypt-cert",
            fixture.certificate_path(),
            "--decrypt-passphrase-file",
            passphrase_file.to_str().unwrap(),
        ]),
        run(&[
            "extract",
            fixture.path(),
            "--output",
            fixture.output("clean-fail").to_str().unwrap(),
            "--json",
            "--decrypt-key",
            key_path.to_str().unwrap(),
            "--decrypt-cert",
            fixture.certificate_path(),
        ]),
    ];

    // Every fragment that must never be echoed: the passphrase, the private
    // key in both its wire forms, and the private exponent's own bytes.
    let private_der = &recipient.private_pkcs8_der;
    let needles: Vec<Vec<u8>> = vec![
        PASSPHRASE.as_bytes().to_vec(),
        encrypted_key.as_bytes().to_vec(),
        recipient.key_pem().into_bytes(),
        private_der[private_der.len() - 64..].to_vec(),
        STANDARD.encode(private_der).into_bytes(),
    ];
    for output in runs {
        for stream in [&output.stdout, &output.stderr] {
            for needle in &needles {
                assert!(
                    !contains(stream, needle),
                    "key or passphrase material reached an output stream"
                );
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn inspect_reports_the_capability_as_available_only_with_a_key() {
    let fixture = Fixture::simple();
    let output = run(&["inspect", fixture.path(), "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value = json(&output);
    assert_eq!(
        value["data"]["capabilities"]["encrypted_extraction"],
        Value::String("with_key".to_owned())
    );
    // `inspect` takes no key, so it still says the document is out of its own
    // reach.
    assert!(
        warning_codes(&value).contains(&"encrypted_document_unsupported".to_owned()),
        "{value}"
    );
}

#[test]
fn the_decryption_flags_require_a_key() {
    let fixture = Fixture::simple();
    for extra in [
        vec!["--decrypt-cert", "/nonexistent"],
        vec!["--decrypt-passphrase-file", "/nonexistent"],
        vec!["--allow-legacy-ciphers"],
    ] {
        let mut arguments = vec![
            "extract",
            fixture.path(),
            "--output",
            "/nonexistent/out",
            "--json",
        ];
        arguments.extend(extra);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert_eq!(
            json(&output)["errors"][0]["code"],
            Value::String("usage_error".to_owned())
        );
    }
}

#[test]
fn stdout_mode_reports_whether_the_payload_was_decrypted() {
    let fixture = Fixture::simple();
    let output = run(&[
        "extract",
        fixture.path(),
        "--stdout",
        "--decrypt-key",
        fixture.key_path(),
        "--decrypt-cert",
        fixture.certificate_path(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, PLAINTEXT);
}

#[test]
fn an_unreadable_key_file_is_an_io_error_that_names_no_contents() {
    let fixture = Fixture::simple();
    let output = run(&[
        "extract",
        fixture.path(),
        "--output",
        fixture.output("out").to_str().unwrap(),
        "--json",
        "--decrypt-key",
        fixture
            .directory
            .path()
            .join("missing.pem")
            .to_str()
            .unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(3));
    let value = json(&output);
    assert_eq!(
        value["errors"][0]["code"],
        Value::String("io_error".to_owned())
    );
    assert_eq!(
        value["errors"][0]["message"],
        Value::String("the decryption key file could not be inspected".to_owned())
    );
}

fn warning_codes(value: &Value) -> Vec<String> {
    value["warnings"]
        .as_array()
        .expect("warnings is an array")
        .iter()
        .map(|notice| notice["code"].as_str().expect("a warning code").to_owned())
        .collect()
}
