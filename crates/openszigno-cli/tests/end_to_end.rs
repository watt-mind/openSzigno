//! End-to-end `verify` runs over a dossier that actually verifies.
//!
//! These are the tests that hold the exit-status contract honest: a run that
//! reaches `valid` must exit `0`, and every way of taking one input away from
//! that run must take the exit status back up.
//!
//! The synthetic PKI and the XMLDSig signer live in
//! `crates/openszigno-verify/tests/common` and are included from here rather
//! than copied, so there is exactly one place in the repository that can sign
//! anything. Signing remains a permanent non-goal of the shipped tool.

#[path = "../../openszigno-verify/tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{
    CertSpec, CrlSpec, DossierSpec, RevokedSpec, SigSpec, SigningCertificateSpec, TestKey,
    TimestampSpec, TlService, TrustListSpec, build, build_crl, build_trust_list,
    document_signature, extended_key_usage_extension, issued_by, keys, qc_statements_extension,
    rsa_key, self_signed,
};
use rcgen::BasicConstraints;
use serde_json::Value;

const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const AT: &str = "2020-06-02T00:00:00Z";

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("the test binary has a path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("openszigno")
}

fn run(arguments: &[&str]) -> Output {
    Command::new(binary())
        .args(arguments)
        .output()
        .expect("the binary runs")
}

fn status(output: &Output) -> i32 {
    output.status.code().expect("the process exited normally")
}

fn parse_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON object")
}

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("openszigno-e2e-")
        .tempdir()
        .expect("a scratch directory is created")
}

/// A root, a signer, and a timestamp authority, plus the certificate the
/// synthetic trusted list is signed with.
struct Pki {
    root_der: Vec<u8>,
    signer_der: Vec<u8>,
    signer_key: TestKey,
    tsa_der: Vec<u8>,
    tl_signer_der: Vec<u8>,
}

fn pki() -> Pki {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let tsa_key = rsa_key(keys::THIRD_RSA2048);

    let root = self_signed(
        &CertSpec::ca(
            "openSzigno Test Qualified CA",
            BasicConstraints::Unconstrained,
        ),
        &root_key,
    );
    let mut signer_spec = CertSpec::signer("openSzigno Test Signer");
    signer_spec.custom_extensions = vec![qc_statements_extension(&["0.4.0.1862.1.1"])];
    let signer = issued_by(&signer_spec, &signer_key, &root, &root_key);
    let mut tsa_spec = CertSpec::signer("openSzigno Test TSA");
    tsa_spec.custom_extensions = vec![extended_key_usage_extension(&[ID_KP_TIME_STAMPING], true)];
    let tsa = issued_by(&tsa_spec, &tsa_key, &root, &root_key);
    let tl_signer = self_signed(
        &CertSpec::signer("openSzigno Test Trusted List Signer"),
        &rsa_key(keys::SECOND_RSA2048),
    );

    Pki {
        root_der: root.der,
        signer_der: signer.der,
        signer_key,
        tsa_der: tsa.der,
        tl_signer_der: tl_signer.der,
    }
}

fn signature(pki: &Pki) -> SigSpec {
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(pki.signer_der.clone()));
    let mut timestamp = TimestampSpec::new(
        rsa_key(keys::THIRD_RSA2048),
        pki.tsa_der.clone(),
        "2020-06-01T09:00:00Z",
    );
    timestamp.token_certificates = vec![pki.root_der.clone()];
    signature.timestamp = Some(timestamp);
    signature
}

fn dossier(pki: &Pki, signature: SigSpec) -> String {
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    build(&spec, &[("doc", &pki.signer_key)])
}

fn write_pem(path: &Path, label: &str, der: &[u8]) {
    let body = pem_rfc7468_encode(label, der);
    std::fs::write(path, body).expect("the file is written");
}

/// A tiny PEM writer, so the fixtures are the shape a real operator's store is.
fn pem_rfc7468_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("Base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Lay out a `--trust-store` and a `--revocation-store` for one PKI.
struct Stores {
    directory: tempfile::TempDir,
}

impl Stores {
    fn new(pki: &Pki, crls: &[Vec<u8>]) -> Self {
        let directory = scratch();
        let trust = directory.path().join("trust/anchors");
        std::fs::create_dir_all(&trust).expect("the trust store is created");
        write_pem(&trust.join("root.pem"), "CERTIFICATE", &pki.root_der);

        let revocation = directory.path().join("revocation/crls");
        std::fs::create_dir_all(&revocation).expect("the revocation store is created");
        for (index, crl) in crls.iter().enumerate() {
            std::fs::write(revocation.join(format!("{index}.crl")), crl)
                .expect("the CRL is written");
        }
        Self { directory }
    }

    fn trust(&self) -> PathBuf {
        self.directory.path().join("trust")
    }

    fn revocation(&self) -> PathBuf {
        self.directory.path().join("revocation")
    }
}

fn write_dossier(directory: &tempfile::TempDir, xml: &str) -> PathBuf {
    let path = directory.path().join("signed.es3");
    std::fs::write(&path, xml).expect("the dossier is written");
    path
}

// ---------------------------------------------------------------------------
// The exit-status contract
// ---------------------------------------------------------------------------

/// The headline of phase 3: a complete signature verifies and the process
/// exits `0`.
#[test]
fn a_complete_signature_exits_zero() {
    let pki = pki();
    let stores = Stores::new(
        &pki,
        &[build_crl(&CrlSpec::new(
            pki.root_der.clone(),
            rsa_key(keys::ROOT_RSA2048),
        ))],
    );
    let directory = scratch();
    let path = write_dossier(&directory, &dossier(&pki, signature(&pki)));

    let output = run(&[
        "verify",
        path.to_str().unwrap(),
        "--json",
        "--at",
        AT,
        "--trust-store",
        stores.trust().to_str().unwrap(),
        "--revocation-store",
        stores.revocation().to_str().unwrap(),
    ]);
    assert_eq!(
        status(&output),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = parse_json(&output);
    assert_eq!(response["ok"], true);
    assert_eq!(response["data"]["verdict"], "valid");
    assert_eq!(response["data"]["counts"]["signatures_valid"], 1);
    assert_eq!(response["data"]["policy"]["revocation"], "offline");
    // The per-certificate revocation answer is in the chain entry, with its
    // source, so a consumer never has to guess where the answer came from.
    let leaf = &response["data"]["signatures"][0]["chain"][0];
    assert_eq!(leaf["revocation"]["status"], "good");
    assert_eq!(leaf["revocation"]["source"], "store_crl");
    // The anchor came from a directory, so qualified status is undetermined.
    assert_eq!(response["data"]["signatures"][0]["qualified"], Value::Null);
    let anchor = response["data"]["signatures"][0]["chain"]
        .as_array()
        .expect("an array")
        .last()
        .expect("an anchor");
    assert_eq!(anchor["trust_anchor_origin"], "trust_store");
}

/// The same dossier with the signer's certificate revoked exits `6`.
#[test]
fn a_revoked_signer_exits_six() {
    let pki = pki();
    let crl = build_crl(
        &CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048))
            .revoking(RevokedSpec::new(&pki.signer_der, "2020-05-10T00:00:00Z")),
    );
    let stores = Stores::new(&pki, &[crl]);
    let directory = scratch();
    let path = write_dossier(&directory, &dossier(&pki, signature(&pki)));

    let output = run(&[
        "verify",
        path.to_str().unwrap(),
        "--json",
        "--at",
        AT,
        "--trust-store",
        stores.trust().to_str().unwrap(),
        "--revocation-store",
        stores.revocation().to_str().unwrap(),
    ]);
    assert_eq!(status(&output), 6);
    let response = parse_json(&output);
    assert_eq!(response["data"]["verdict"], "invalid");
    let codes: Vec<&str> = response["data"]["signatures"][0]["checks"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|check| check["code"].as_str().expect("a string"))
        .collect();
    assert!(codes.contains(&"cert_revoked"));
}

/// `--no-revocation` caps the same run at `indeterminate` and exit `7`, which
/// is the documented cost of switching the check off.
#[test]
fn no_revocation_caps_the_verdict_at_indeterminate() {
    let pki = pki();
    let stores = Stores::new(
        &pki,
        &[build_crl(&CrlSpec::new(
            pki.root_der.clone(),
            rsa_key(keys::ROOT_RSA2048),
        ))],
    );
    let directory = scratch();
    let path = write_dossier(&directory, &dossier(&pki, signature(&pki)));

    let output = run(&[
        "verify",
        path.to_str().unwrap(),
        "--json",
        "--at",
        AT,
        "--trust-store",
        stores.trust().to_str().unwrap(),
        "--no-revocation",
    ]);
    assert_eq!(status(&output), 7);
    let response = parse_json(&output);
    assert_eq!(response["data"]["verdict"], "indeterminate");
    assert_eq!(response["data"]["policy"]["revocation"], "not_checked");
    let codes: Vec<&str> = response["data"]["signatures"][0]["checks"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|check| check["code"].as_str().expect("a string"))
        .collect();
    assert!(codes.contains(&"revocation_not_checked"));
}

/// Without any revocation material the run is `indeterminate` too: the
/// difference between "not checked" and "could not be answered" is reported,
/// but neither reaches `valid`.
#[test]
fn missing_revocation_data_is_indeterminate() {
    let pki = pki();
    let stores = Stores::new(&pki, &[]);
    let directory = scratch();
    let path = write_dossier(&directory, &dossier(&pki, signature(&pki)));

    let output = run(&[
        "verify",
        path.to_str().unwrap(),
        "--json",
        "--at",
        AT,
        "--trust-store",
        stores.trust().to_str().unwrap(),
    ]);
    assert_eq!(status(&output), 7);
    let response = parse_json(&output);
    let codes: Vec<&str> = response["data"]["signatures"][0]["checks"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|check| check["code"].as_str().expect("a string"))
        .collect();
    assert!(codes.contains(&"revocation_status_unknown"));
}

// ---------------------------------------------------------------------------
// Stores and trusted lists
// ---------------------------------------------------------------------------

/// A revocation-store file that is neither a CRL nor an OCSP response fails
/// the run: a half-loaded store would silently change what "no data" means.
#[test]
fn an_unusable_revocation_store_file_fails_the_run() {
    let pki = pki();
    let stores = Stores::new(&pki, &[]);
    std::fs::write(stores.revocation().join("crls/junk.crl"), b"not DER at all")
        .expect("the junk file is written");
    let directory = scratch();
    let path = write_dossier(&directory, &dossier(&pki, signature(&pki)));

    let output = run(&[
        "verify",
        path.to_str().unwrap(),
        "--json",
        "--trust-store",
        stores.trust().to_str().unwrap(),
        "--revocation-store",
        stores.revocation().to_str().unwrap(),
    ]);
    assert_eq!(status(&output), 3);
    let response = parse_json(&output);
    assert_eq!(response["ok"], false);
    assert_eq!(response["errors"][0]["code"], "revocation_store_invalid");
    // The message names what was wrong, never which file it was.
    let message = response["errors"][0]["message"]
        .as_str()
        .expect("a message");
    assert!(
        message.contains("neither a CRL nor an OCSP response"),
        "{message}"
    );
    assert!(!message.contains("junk"), "{message}");
}

/// A trusted list supplies the anchor, the qualified determination follows from
/// it, and the run still exits `0`.
#[test]
fn a_trusted_list_supplies_a_qualified_anchor() {
    let pki = pki();
    let stores = Stores::new(
        &pki,
        &[build_crl(&CrlSpec::new(
            pki.root_der.clone(),
            rsa_key(keys::ROOT_RSA2048),
        ))],
    );
    let directory = scratch();
    let path = write_dossier(&directory, &dossier(&pki, signature(&pki)));

    let mut spec = TrustListSpec::new(vec![TlService::ca_qc(
        "openSzigno Test Qualified CA",
        pki.root_der.clone(),
    )]);
    spec.signer = Some((rsa_key(keys::SECOND_RSA2048), pki.tl_signer_der.clone()));
    let list_path = directory.path().join("HU_TL.xml");
    std::fs::write(&list_path, build_trust_list(&spec)).expect("the list is written");
    let signer_path = directory.path().join("tl-signer.pem");
    write_pem(&signer_path, "CERTIFICATE", &pki.tl_signer_der);

    let output = run(&[
        "verify",
        path.to_str().unwrap(),
        "--json",
        "--at",
        AT,
        "--trust-list",
        list_path.to_str().unwrap(),
        "--trust-list-signer",
        signer_path.to_str().unwrap(),
        "--revocation-store",
        stores.revocation().to_str().unwrap(),
    ]);
    assert_eq!(
        status(&output),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = parse_json(&output);
    assert_eq!(response["data"]["verdict"], "valid");
    assert_eq!(response["data"]["signatures"][0]["qualified"], true);
    let anchor = response["data"]["signatures"][0]["chain"]
        .as_array()
        .expect("an array")
        .last()
        .expect("an anchor");
    assert_eq!(anchor["trust_anchor_origin"], "trust_list");
    // The snapshot the run relied on is cited in the policy block.
    let snapshot = &response["data"]["policy"]["trust_lists"][0];
    assert_eq!(snapshot["territory"], "HU");
    assert_eq!(snapshot["sequence_number"], 7);
    assert_eq!(snapshot["signature_verified"], true);
}

/// Without `--trust-list-signer` the list is used but reported as unverified,
/// which is blocking: exit `7`, never `0`.
#[test]
fn an_unverified_trusted_list_cannot_reach_valid() {
    let pki = pki();
    let stores = Stores::new(
        &pki,
        &[build_crl(&CrlSpec::new(
            pki.root_der.clone(),
            rsa_key(keys::ROOT_RSA2048),
        ))],
    );
    let directory = scratch();
    let path = write_dossier(&directory, &dossier(&pki, signature(&pki)));
    let list_path = directory.path().join("HU_TL.xml");
    std::fs::write(
        &list_path,
        build_trust_list(&TrustListSpec::new(vec![TlService::ca_qc(
            "openSzigno Test Qualified CA",
            pki.root_der.clone(),
        )])),
    )
    .expect("the list is written");

    let output = run(&[
        "verify",
        path.to_str().unwrap(),
        "--json",
        "--at",
        AT,
        "--trust-list",
        list_path.to_str().unwrap(),
        "--revocation-store",
        stores.revocation().to_str().unwrap(),
    ]);
    assert_eq!(status(&output), 7);
    let response = parse_json(&output);
    let codes: Vec<&str> = response["data"]["checks"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|check| check["code"].as_str().expect("a string"))
        .collect();
    assert!(codes.contains(&"trust_list_unverified"));
    assert_eq!(
        response["data"]["policy"]["trust_lists"][0]["signature_verified"],
        false
    );
}

/// A `--trust-list` file that is not a trusted list fails the run rather than
/// contributing nothing quietly.
#[test]
fn an_unusable_trust_list_fails_the_run() {
    let pki = pki();
    let directory = scratch();
    let path = write_dossier(&directory, &dossier(&pki, signature(&pki)));
    let list_path = directory.path().join("not-a-list.xml");
    std::fs::write(&list_path, "<hello/>").expect("the file is written");

    let output = run(&[
        "verify",
        path.to_str().unwrap(),
        "--json",
        "--trust-list",
        list_path.to_str().unwrap(),
    ]);
    assert_eq!(status(&output), 3);
    assert_eq!(
        parse_json(&output)["errors"][0]["code"],
        "trust_list_invalid"
    );
}

/// Human output states the verdict and the policy it was reached under.
#[test]
fn human_output_states_the_policy() {
    let pki = pki();
    let stores = Stores::new(
        &pki,
        &[build_crl(&CrlSpec::new(
            pki.root_der.clone(),
            rsa_key(keys::ROOT_RSA2048),
        ))],
    );
    let directory = scratch();
    let path = write_dossier(&directory, &dossier(&pki, signature(&pki)));

    let output = run(&[
        "verify",
        path.to_str().unwrap(),
        "--at",
        AT,
        "--trust-store",
        stores.trust().to_str().unwrap(),
        "--revocation-store",
        stores.revocation().to_str().unwrap(),
    ]);
    assert_eq!(status(&output), 0);
    let text = String::from_utf8(output.stdout).expect("UTF-8");
    assert!(text.contains("Verification verdict: valid"), "{text}");
    assert!(text.contains("Revocation policy: offline"), "{text}");
    assert!(text.contains("not a legal opinion"), "{text}");
}
