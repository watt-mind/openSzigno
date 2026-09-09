//! `sign --csc`, end to end: what a remote service signs is what this tool
//! verifies.
//!
//! Every run here creates a dossier, signs it through the loopback mock CSC
//! service in `csc_support`, and — where the run is meant to succeed — verifies
//! the result against a trust store the test built seconds earlier. That last
//! step is the whole point: under `supportedHashTypes: ["dtbsr"]` the service
//! signs a digest it never sees the document behind, so only verification says
//! whether the canonicalization was right.
//!
//! A `valid` verdict over a synthetic chain means the signature verified
//! against the anchor *this test chose to trust*, and nothing more. It is a
//! statement about the shape of what `sign --csc` writes, never about anybody's
//! identity and never about qualified status.

mod csc_support;

use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;

use csc_support::online_support::common::{
    CertSpec, CrlSpec, TimestampSpec, build_crl, build_timestamp_token_for_imprint,
    extended_key_usage_extension, issued_by, keys, rsa_key, self_signed,
};
use csc_support::online_support::{Reply, json, reserved, run, scratch, serve_on};
use csc_support::{CREDENTIAL, Flavour, Mock, TimeStampReq};
use rcgen::BasicConstraints;
use serde_json::Value;

/// The instant every run is judged at, inside the synthetic certificates'
/// validity and inside the synthetic CRL's freshness window.
const AT: &str = "2020-06-02T00:00:00Z";
/// The `genTime` the loopback timestamp authority stamps with, after the
/// signing time so the token never precedes what it stamps.
const GEN_TIME: &str = "2020-06-02T00:00:10Z";
/// RFC 3161 `id-kp-timeStamping`.
const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
/// The token every configuration in this file carries. It is a synthetic
/// string, it authorises nothing anywhere, and no test may ever find it in an
/// output.
const TOKEN: &str = "synthetic-service-token-never-printed";

// ---------------------------------------------------------------------------
// The fixture: a PKI, a dossier, a mock service, and a configuration
// ---------------------------------------------------------------------------

struct Fixture {
    directory: tempfile::TempDir,
    service: csc_support::Service,
    /// Kept alive for as long as the tests need the authority.
    _tsa: Option<csc_support::online_support::Server>,
    tsa_url: Option<String>,
    root_der: Vec<u8>,
    tsa_der: Vec<u8>,
}

impl Fixture {
    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn text(&self, name: &str) -> String {
        self.path(name).to_str().expect("a UTF-8 path").to_owned()
    }
}

/// Lay out one test's directory: an unsigned dossier, a trust store holding
/// the root, a mock CSC service issued from that root, and a configuration
/// file naming it.
fn fixture(mock: Mock) -> Fixture {
    fixture_with(mock, false)
}

fn fixture_with(mock: Mock, timestamped: bool) -> Fixture {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let material = csc_support::material(mock.flavour, &root, &root_key);
    let root_der = root.der.clone();
    let mut tsa_spec = CertSpec::signer("openSzigno Test TSA");
    tsa_spec.custom_extensions = vec![extended_key_usage_extension(&[ID_KP_TIME_STAMPING], true)];
    let tsa = issued_by(&tsa_spec, &rsa_key(keys::THIRD_RSA2048), &root, &root_key);
    let pin = mock.require_pin.clone();
    let service = csc_support::serve(mock, material);

    let directory = scratch();
    let anchors = directory.path().join("store/anchors");
    std::fs::create_dir_all(&anchors).expect("the anchors directory is created");
    std::fs::write(anchors.join("root.der"), &root_der).expect("the anchor is written");
    let mut config = format!(
        "base_url = \"{}\"\nclient_id = \"openszigno-cli\"\naccess_token = \"{TOKEN}\"\n",
        service.base_url()
    );
    if let Some(pin) = &pin {
        std::fs::write(directory.path().join("pin"), format!("{pin}\n"))
            .expect("the PIN file is written");
        config.push_str("pin_file = \"pin\"\n");
    }
    std::fs::write(directory.path().join("csc.toml"), config)
        .expect("the configuration is written");

    let (tsa_server, tsa_url) = if timestamped {
        let (server, url) = timestamp_authority(&tsa.der, &root_der);
        (Some(server), Some(url))
    } else {
        (None, None)
    };
    let fixture = Fixture {
        directory,
        service,
        _tsa: tsa_server,
        tsa_url,
        root_der,
        tsa_der: tsa.der,
    };
    create(&fixture);
    fixture
}

/// Create the unsigned dossier every run signs.
fn create(fixture: &Fixture) {
    let note = fixture.path("note.txt");
    std::fs::write(&note, "a synthetic document\n").expect("the input is written");
    let output = run(&[
        "create",
        "--output",
        &fixture.text("input.es3"),
        "--title",
        "Synthetic CSC signing fixture",
        "--created",
        "2020-05-02T00:00:00Z",
        "--document",
        &format!("{}::note.txt", note.to_str().expect("a UTF-8 path")),
        "--json",
    ]);
    assert!(output.status.success(), "create failed: {output:?}");
}

/// A revocation store holding one CRL from the root, which answers for both
/// the CSC credential's certificate and the timestamp authority's.
fn revocation_store(fixture: &Fixture) -> String {
    let directory = fixture.path("revocation/crls");
    std::fs::create_dir_all(&directory).expect("the crls directory is created");
    let crl = build_crl(&CrlSpec::new(
        fixture.root_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    ));
    std::fs::write(directory.join("root.crl"), crl).expect("the CRL is written");
    fixture.text("revocation")
}

/// A loopback timestamp authority: it stamps the imprint the request carries
/// and never sees the data.
fn timestamp_authority(
    tsa_der: &[u8],
    root_der: &[u8],
) -> (csc_support::online_support::Server, String) {
    let (listener, address) = reserved();
    let tsa_der = tsa_der.to_vec();
    let root_der = root_der.to_vec();
    let answer = move |body: &[u8]| -> Vec<u8> {
        use der::{Decode as _, Encode as _};
        let request = TimeStampReq::from_der(body).expect("the CLI sent a TimeStampReq");
        let mut spec = TimestampSpec::new(rsa_key(keys::THIRD_RSA2048), tsa_der.clone(), GEN_TIME);
        spec.token_certificates = vec![root_der.clone()];
        let token = build_timestamp_token_for_imprint(
            &spec,
            request.message_imprint.hashed_message.as_bytes(),
        );
        openszigno_verify::tsa::TimeStampResp {
            status: openszigno_verify::tsa::PkiStatusInfo {
                status: 0,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: Some(
                cms::content_info::ContentInfo::from_der(&token).expect("the token decodes"),
            ),
        }
        .to_der()
        .expect("the response encodes")
    };
    let server = serve_on(
        listener,
        address,
        vec![("/tsa", Reply::Computed(Arc::new(answer)))],
    );
    let url = format!("http://{address}/tsa");
    (server, url)
}

// ---------------------------------------------------------------------------
// Running the CLI
// ---------------------------------------------------------------------------

/// One `sign --csc` run against the mock service.
fn sign(fixture: &Fixture, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "sign".to_owned(),
        fixture.text("input.es3"),
        "--output".to_owned(),
        fixture.text("signed.es3"),
        "--csc".to_owned(),
        fixture.text("csc.toml"),
        "--signing-time".to_owned(),
        AT.to_owned(),
        // The mock serves from 127.0.0.1, which the destination policy refuses
        // by default and which is also what makes a plain-http CSC base URL
        // acceptable. Both are the same opt-in.
        "--online-allow-private".to_owned(),
        "--json".to_owned(),
    ];
    arguments.extend(extra.iter().map(|value| (*value).to_owned()));
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    run(&borrowed)
}

fn verify(fixture: &Fixture, extra: &[&str]) -> Value {
    let mut arguments = vec![
        "verify".to_owned(),
        fixture.text("signed.es3"),
        "--trust-store".to_owned(),
        fixture.text("store"),
        "--at".to_owned(),
        AT.to_owned(),
        "--json".to_owned(),
    ];
    arguments.extend(extra.iter().map(|value| (*value).to_owned()));
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    json(&run(&borrowed))
}

/// The check codes that block a `valid` verdict.
fn blocking(report: &Value) -> Vec<String> {
    let mut codes = Vec::new();
    for list in [
        report["data"]["checks"].as_array(),
        report["data"]["signatures"][0]["checks"].as_array(),
    ] {
        for check in list.into_iter().flatten() {
            let status = check["status"].as_str().unwrap_or_default();
            if status != "passed" && status != "info" {
                codes.push(check["code"].as_str().unwrap_or_default().to_owned());
            }
        }
    }
    codes.sort();
    codes.dedup();
    codes
}

/// Every byte the run wrote anywhere a person or an agent would read.
fn everything_printed(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// ---------------------------------------------------------------------------
// The three personalities
// ---------------------------------------------------------------------------

/// Each surveyed service shape signs, and the client picks the algorithm the
/// credential published rather than one it assumed.
#[test]
fn every_surveyed_service_shape_produces_a_signature_this_tool_verifies() {
    for (flavour, algorithm, specs) in [
        (Flavour::Eudi, "ecdsa-p256-sha256", "2.2.0.0"),
        (Flavour::PrimeSign, "rsa-pss-sha256", "2.1.0.1"),
        (Flavour::Cleverbase, "ecdsa-p256-sha256", "2.2.0.0"),
    ] {
        let fixture = fixture(Mock::new(flavour));
        let output = sign(&fixture, &[]);
        assert!(output.status.success(), "{flavour:?}: {output:?}");
        let report = json(&output);
        let signature = &report["data"]["signatures"][0];
        assert_eq!(signature["signer"], "csc", "{flavour:?}");
        assert_eq!(signature["algorithm"], algorithm, "{flavour:?}");
        assert_eq!(signature["credential_id"], CREDENTIAL, "{flavour:?}");
        assert_eq!(signature["csc_specs"], specs, "{flavour:?}");

        // The discovery calls happen once, in order, before anything is
        // signed; then one authorisation and one signature.
        assert_eq!(
            fixture.service.paths(),
            vec![
                "/csc/v2/info",
                "/csc/v2/credentials/list",
                "/csc/v2/credentials/info",
                "/csc/v2/credentials/authorize",
                "/csc/v2/signatures/signHash",
            ],
            "{flavour:?}"
        );

        // And the whole point: the digest that was signed was the right one.
        // Without a timestamp the verdict is capped at `indeterminate` by
        // `signature_timestamp_absent`, exactly as it is for a local key, and
        // that one code is the only thing left blocking.
        let store = revocation_store(&fixture);
        let report = verify(&fixture, &["--revocation-store", &store]);
        assert_eq!(
            blocking(&report),
            vec!["signature_timestamp_absent".to_owned()],
            "{flavour:?}"
        );
    }
}

/// The chain the service published becomes `xades:CertificateValues`, so
/// `--chain` stays optional: nothing in the run above named the root, and the
/// verifier still built the path.
#[test]
fn the_chain_the_service_published_is_what_the_verifier_builds_the_path_from() {
    let fixture = fixture(Mock::new(Flavour::Eudi));
    assert!(sign(&fixture, &[]).status.success());
    let signed = std::fs::read_to_string(fixture.path("signed.es3")).expect("the output is read");
    assert!(signed.contains("CertificateValues"));
    let store = revocation_store(&fixture);
    let report = verify(&fixture, &["--revocation-store", &store]);
    assert_eq!(
        blocking(&report),
        vec!["signature_timestamp_absent".to_owned()]
    );
}

// ---------------------------------------------------------------------------
// Authorisation
// ---------------------------------------------------------------------------

/// An explicit-mode credential is authorised with the PIN from a file, and the
/// PIN never appears in `argv` or in any output.
#[test]
fn an_explicit_credential_is_authorised_with_a_pin_from_a_file() {
    let mut mock = Mock::new(Flavour::Cleverbase);
    mock.require_pin = Some("135790".to_owned());
    let fixture = fixture(mock);
    let output = sign(&fixture, &[]);
    assert!(output.status.success(), "{output:?}");
    assert!(!everything_printed(&output).contains("135790"));

    // Without the PIN the service refuses the authorisation, and the run stops
    // there with the status and the service's own error string.
    let mut mock = Mock::new(Flavour::Cleverbase);
    mock.require_pin = Some("135790".to_owned());
    let fixture = fixture_no_pin(mock);
    let output = sign(&fixture, &[]);
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "csc_rejected");
    assert!(
        report["errors"][0]["message"]
            .as_str()
            .expect("a message")
            .contains("400")
    );
    assert!(
        report["errors"][0]["message"]
            .as_str()
            .expect("a message")
            .contains("invalid_pin")
    );
    assert!(!fixture.path("signed.es3").exists());
}

/// The same fixture, with the PIN file deliberately left out.
fn fixture_no_pin(mut mock: Mock) -> Fixture {
    let required = mock.require_pin.take();
    let fixture = fixture(Mock {
        require_pin: required,
        ..mock
    });
    // `fixture` writes the PIN file whenever the mock wants one; this case
    // needs the service to want one and the configuration not to have it.
    let path = fixture.path("csc.toml");
    let text = std::fs::read_to_string(&path).expect("the configuration is read");
    std::fs::write(
        &path,
        text.lines()
            .filter(|line| !line.starts_with("pin_file"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("the configuration is rewritten");
    fixture
}

/// An `oauth2`-mode credential cannot be authorised without a browser, so the
/// run stops before the dossier is touched and says which flow to complete.
#[test]
fn an_oauth2_credential_is_refused_with_the_flow_to_complete() {
    let mut mock = Mock::new(Flavour::Eudi);
    mock.auth_mode = "oauth2";
    let fixture = fixture(mock);
    let output = sign(&fixture, &[]);
    assert!(!output.status.success());
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "csc_authorization_required");
    let message = report["errors"][0]["message"].as_str().expect("a message");
    assert!(message.contains("scope=credential"));
    assert!(message.contains("csc login"));
    // Nothing was authorised and nothing was written.
    assert!(!fixture.service.paths().iter().any(|p| p.contains("sign")));
    assert!(!fixture.path("signed.es3").exists());
}

/// Several credentials and none named is a refusal that lists them, because
/// which qualified certificate signs is the user's decision.
#[test]
fn several_credentials_are_never_guessed_between_and_one_may_be_named() {
    let mut mock = Mock::new(Flavour::Eudi);
    mock.credential_ids = vec![CREDENTIAL.to_owned(), "cred-other".to_owned()];
    let fixture = fixture(mock);
    let report = json(&sign(&fixture, &[]));
    assert_eq!(report["errors"][0]["code"], "csc_credential_ambiguous");
    let message = report["errors"][0]["message"].as_str().expect("a message");
    assert!(message.contains(CREDENTIAL) && message.contains("cred-other"));

    // Naming one skips credentials/list entirely.
    let output = sign(&fixture, &["--csc-credential", CREDENTIAL]);
    assert!(output.status.success(), "{output:?}");
    assert!(
        !fixture
            .service
            .paths()
            .iter()
            .skip_while(|path| *path != "/csc/v2/credentials/info")
            .any(|path| path == "/csc/v2/credentials/list")
    );
}

// ---------------------------------------------------------------------------
// The signature is checked before anything is written
// ---------------------------------------------------------------------------

/// A service that returns a signature over other bytes is caught locally, and
/// no file is written.
///
/// This is the failure the whole design turns on: under `dtbsr` the service
/// never sees the document, so a wrong signature is perfectly well formed and
/// only a local check tells it from a right one.
#[test]
fn a_signature_that_does_not_verify_is_refused_and_nothing_is_written() {
    let mut mock = Mock::new(Flavour::Eudi);
    mock.wrong_signature = true;
    let fixture = fixture(mock);
    let output = sign(&fixture, &[]);
    assert!(!output.status.success());
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "csc_signature_invalid");
    let message = report["errors"][0]["message"].as_str().expect("a message");
    assert!(message.contains("nothing was written"));
    assert!(!fixture.path("signed.es3").exists());
}

// ---------------------------------------------------------------------------
// The token
// ---------------------------------------------------------------------------

/// The bearer token reaches the service in the `Authorization` header, and
/// reaches nothing else: not stdout, not stderr, not the file that was
/// written.
#[test]
fn the_bearer_token_travels_in_a_header_and_appears_nowhere_else() {
    let signed_run = fixture(Mock::new(Flavour::Eudi));
    let output = sign(&signed_run, &[]);
    assert!(output.status.success(), "{output:?}");
    let seen = signed_run.service.authorizations();
    assert_eq!(seen.len(), 5, "one per operation");
    assert!(seen.iter().all(|value| value == &format!("Bearer {TOKEN}")));

    assert!(!everything_printed(&output).contains(TOKEN));
    let signed =
        std::fs::read_to_string(signed_run.path("signed.es3")).expect("the output is read");
    assert!(!signed.contains(TOKEN));

    // A refused run must not print it either.
    let mut mock = Mock::new(Flavour::Eudi);
    mock.auth_mode = "oauth2";
    let refused_fixture = fixture(mock);
    assert!(!everything_printed(&sign(&refused_fixture, &[])).contains(TOKEN));
}

// ---------------------------------------------------------------------------
// Configuration and flag refusals
// ---------------------------------------------------------------------------

/// `--csc` and `--key` are two backends for one seam, and asking for both is a
/// usage error rather than a silent preference.
#[test]
fn csc_and_a_local_key_are_mutually_exclusive() {
    let fixture = fixture(Mock::new(Flavour::Eudi));
    let output = run(&[
        "sign",
        &fixture.text("input.es3"),
        "--output",
        &fixture.text("signed.es3"),
        "--csc",
        &fixture.text("csc.toml"),
        "--key",
        &fixture.text("csc.toml"),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "usage_error");
}

/// A configuration that cannot be used stops the run with a stable code,
/// before a socket is opened.
#[test]
fn an_unusable_configuration_is_refused_before_anything_is_contacted() {
    let fixture = fixture(Mock::new(Flavour::Eudi));
    std::fs::write(fixture.path("broken.toml"), "base_url = \"https://q\"\n")
        .expect("the configuration is written");
    let output = run(&[
        "sign",
        &fixture.text("input.es3"),
        "--output",
        &fixture.text("signed.es3"),
        "--csc",
        &fixture.text("broken.toml"),
        "--json",
    ]);
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "csc_config_invalid");
    assert_eq!(output.status.code(), Some(4));
    assert!(fixture.service.paths().is_empty());
}

/// A plain-http service is refused without `--online-allow-private`, because
/// the token travels in a header.
#[test]
fn a_plaintext_service_is_refused_without_the_opt_in() {
    let fixture = fixture(Mock::new(Flavour::Eudi));
    let output = run(&[
        "sign",
        &fixture.text("input.es3"),
        "--output",
        &fixture.text("signed.es3"),
        "--csc",
        &fixture.text("csc.toml"),
        "--json",
    ]);
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "csc_config_invalid");
    assert!(
        report["errors"][0]["message"]
            .as_str()
            .expect("a message")
            .contains("https")
    );
    assert!(fixture.service.paths().is_empty());
}

/// A service that is not there is `csc_unreachable`, with the transport's own
/// failure class so the remedy is visible.
#[test]
fn a_service_that_is_not_there_is_unreachable() {
    let fixture = fixture(Mock::new(Flavour::Eudi));
    // A port nothing is listening on: bound and immediately released.
    let (listener, address) = reserved();
    drop(listener);
    std::fs::write(
        fixture.path("gone.toml"),
        format!(
            "base_url = \"http://{address}/csc/v2\"\nclient_id = \"a\"\naccess_token = \"{TOKEN}\"\n"
        ),
    )
    .expect("the configuration is written");
    let output = run(&[
        "sign",
        &fixture.text("input.es3"),
        "--output",
        &fixture.text("signed.es3"),
        "--csc",
        &fixture.text("gone.toml"),
        "--online-allow-private",
        "--json",
    ]);
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "csc_unreachable");
    assert_eq!(output.status.code(), Some(5));
    assert!(!everything_printed(&output).contains(TOKEN));
}

// ---------------------------------------------------------------------------
// The whole thing, with a timestamp
// ---------------------------------------------------------------------------

/// Create, sign with `--csc` against the mock plus a loopback timestamp
/// authority, and verify against a generated CRL: `valid`.
///
/// This is the shape section 6.2 of `docs/remote-signing.md` names as the
/// target — a XAdES-T frame signature with a qualified certificate and a
/// timestamp — assembled end to end from parts this repository builds.
#[test]
fn a_timestamped_remote_signature_verifies_end_to_end() {
    let fixture = fixture_with(Mock::new(Flavour::Eudi), true);
    let tsa_certificate = fixture.path("tsa.crt");
    std::fs::write(&tsa_certificate, &fixture.tsa_der).expect("the TSA certificate is written");
    let url = fixture.tsa_url.clone().expect("the authority is running");
    let output = sign(
        &fixture,
        &[
            "--tsa",
            &url,
            "--tsa-cert",
            tsa_certificate.to_str().expect("a UTF-8 path"),
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let report = json(&output);
    assert_eq!(report["data"]["signatures"][0]["timestamped"], true);
    assert_eq!(report["data"]["signatures"][0]["signer"], "csc");

    let store = revocation_store(&fixture);
    let report = verify(&fixture, &["--revocation-store", &store]);
    assert_eq!(
        report["data"]["verdict"],
        "valid",
        "{:?}",
        blocking(&report)
    );
}

// ---------------------------------------------------------------------------
// Redirects, and the header that must not follow one
// ---------------------------------------------------------------------------

/// A CSC service that answers `info` with a `302` to another loopback port is
/// asking the client to carry its bearer token somewhere the operator never
/// configured. The redirect is refused, and the target sees no request at all:
/// the `Authorization` header is attached only after a target has passed the
/// destination policy and the redirect rules, so a target that failed them
/// never gets one.
#[test]
fn a_csc_redirect_off_the_configured_host_is_refused_and_the_target_sees_nothing() {
    let (listener, sink) = reserved();
    let sink_server = serve_on(listener, sink, vec![("/csc/v2/info", Reply::Status(200))]);
    let mut mock = Mock::new(Flavour::Eudi);
    mock.redirect_info_to = Some(format!("http://{sink}/csc/v2/info"));
    let fixture = fixture(mock);

    let output = sign(&fixture, &[]);
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "csc_unreachable");
    let message = report["errors"][0]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(message.contains("info"), "{message}");
    assert!(message.contains("redirect"), "{message}");
    assert_eq!(output.status.code(), Some(5));

    // Nothing reached the redirect target, so nothing carried the token there.
    let seen = sink_server.seen();
    assert!(
        seen.is_empty(),
        "the redirect target was contacted: {seen:?}"
    );
    assert!(
        seen.iter().all(|request| request.authorization.is_none()),
        "the redirect target was sent an Authorization header"
    );
    assert!(!everything_printed(&output).contains(TOKEN));
}

// ---------------------------------------------------------------------------
// Nothing a service says reaches a terminal unfiltered
// ---------------------------------------------------------------------------

/// A credential identifier the service chose, carrying an ANSI erase-line
/// sequence and a right-to-left override, JSON-escaped because the mock
/// quotes the identifiers it is given verbatim into its answer.
const HOSTILE_CREDENTIAL: &str = r"cred\u001b[2K\u202edrowssap\u202c-1";

/// What is left of it once the display sanitiser has run: the visible
/// characters, and nothing a terminal would act on.
const HOSTILE_CREDENTIAL_SANITIZED: &str = "cred[2Kdrowssap-1";

/// One `sign --csc` run in human mode, so what a terminal receives is exactly
/// what this asserts on.
fn sign_human(fixture: &Fixture) -> Output {
    run(&[
        "sign",
        &fixture.text("input.es3"),
        "--output",
        &fixture.text("signed.es3"),
        "--csc",
        &fixture.text("csc.toml"),
        "--signing-time",
        AT,
        "--online-allow-private",
    ])
}

/// A credential identifier is service-supplied text. It reaches the JSON
/// envelope, human output and an error message only through the sanitiser, so
/// no service can move a cursor, repaint a line, or reverse the reading order
/// of what is printed around it.
#[test]
fn a_hostile_credential_identifier_never_reaches_a_terminal_intact() {
    let mut mock = Mock::new(Flavour::Eudi);
    mock.credential_ids = vec![HOSTILE_CREDENTIAL.to_owned()];
    let reported = fixture(mock);
    let output = sign(&reported, &[]);
    assert!(output.status.success(), "{output:?}");
    let report = json(&output);
    assert_eq!(
        report["data"]["signatures"][0]["credential_id"],
        HOSTILE_CREDENTIAL_SANITIZED
    );
    let printed = everything_printed(&output);
    assert!(!printed.contains('\u{1b}'), "an escape reached the output");
    assert!(
        !printed.contains('\u{202e}'),
        "an override reached the output"
    );

    let mut mock = Mock::new(Flavour::Eudi);
    mock.credential_ids = vec![HOSTILE_CREDENTIAL.to_owned()];
    let human = fixture(mock);
    let output = sign_human(&human);
    assert!(output.status.success(), "{output:?}");
    let printed = everything_printed(&output);
    assert!(
        printed.contains(&format!("credential={HOSTILE_CREDENTIAL_SANITIZED}")),
        "the credential is still named: {printed}"
    );
    assert!(
        !printed.contains('\u{1b}'),
        "an escape reached the terminal"
    );
    assert!(
        !printed.contains('\u{202e}'),
        "an override reached the terminal"
    );
}

/// The same holds for the refusal that lists the credentials on offer, which
/// is the one place several service-chosen strings are joined together.
#[test]
fn a_hostile_credential_identifier_is_sanitized_in_an_error_message() {
    let mut mock = Mock::new(Flavour::Eudi);
    mock.credential_ids = vec![HOSTILE_CREDENTIAL.to_owned(), "cred-other".to_owned()];
    let fixture = fixture(mock);
    let output = sign(&fixture, &[]);
    assert!(!output.status.success());
    let report = json(&output);
    assert_eq!(report["errors"][0]["code"], "csc_credential_ambiguous");
    let message = report["errors"][0]["message"].as_str().expect("a message");
    assert!(
        message.contains(HOSTILE_CREDENTIAL_SANITIZED) && message.contains("cred-other"),
        "both credentials are still listed: {message}"
    );
    let printed = everything_printed(&output);
    assert!(!printed.contains('\u{1b}'), "an escape reached the output");
    assert!(
        !printed.contains('\u{202e}'),
        "an override reached the output"
    );
}
