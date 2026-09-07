use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(args)
        .output()
        .expect("CLI must run")
}

fn parse_json(output: &Output) -> Value {
    assert!(output.stderr.is_empty(), "JSON mode must keep stderr quiet");
    serde_json::from_slice(&output.stdout).expect("stdout must be exactly one JSON value")
}

#[test]
fn inspect_list_and_validate_emit_agent_json() {
    for command in ["inspect", "list", "validate-structure"] {
        let output = run(&[
            command,
            fixture("plain-base64.es3").to_str().unwrap(),
            "--json",
        ]);
        assert!(output.status.success(), "{command} should succeed");
        let response = parse_json(&output);
        assert_eq!(response["schema_version"], 1);
        assert_eq!(response["ok"], true);
        assert_eq!(response["command"], command);
        assert_eq!(response["input"]["format"], "microsec-es3");
        assert!(response["warnings"].is_array());
        assert_eq!(response["errors"], Value::Array(Vec::new()));
    }
}

#[test]
fn extracts_plain_and_zip_payloads_without_clobbering() {
    let directory = tempdir().unwrap();
    let output_dir = directory.path().join("out");
    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 1);
    assert_eq!(
        std::fs::read(output_dir.join("hello.txt")).unwrap(),
        b"Hello from openSzigno synthetic fixture.\n"
    );

    let second = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(second.status.code(), Some(5));
    assert_eq!(parse_json(&second)["errors"][0]["code"], "output_exists");

    let zip_dir = directory.path().join("zip");
    let zip = run(&[
        "extract",
        fixture("zip-base64.es3").to_str().unwrap(),
        "--output",
        zip_dir.to_str().unwrap(),
        "--json",
    ]);
    assert!(zip.status.success());
    assert_eq!(
        std::fs::read(zip_dir.join("zipped.txt")).unwrap(),
        b"Zipped openSzigno synthetic fixture.\n"
    );
}

#[test]
fn emits_stable_errors_for_unsafe_inputs() {
    let duplicate = run(&[
        "validate-structure",
        fixture("duplicate-id.es3").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(duplicate.status.code(), Some(4));
    let response = parse_json(&duplicate);
    assert_eq!(response["ok"], false);
    assert_eq!(response["errors"][0]["code"], "duplicate_id");

    let directory = tempdir().unwrap();
    let traversal = run(&[
        "extract",
        fixture("traversal-title.es3").to_str().unwrap(),
        "--output",
        directory.path().join("out").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(traversal.status.code(), Some(5));
    assert_eq!(
        parse_json(&traversal)["errors"][0]["code"],
        "unsafe_output_name"
    );

    let invalid = run(&[
        "extract",
        fixture("invalid-base64.es3").to_str().unwrap(),
        "--output",
        directory.path().join("invalid").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(invalid.status.code(), Some(5));
    assert_eq!(parse_json(&invalid)["errors"][0]["code"], "invalid_base64");
}

#[test]
fn encrypted_documents_are_skipped_explicitly() {
    let directory = tempdir().unwrap();
    let output = run(&[
        "extract",
        fixture("encrypted.es3").to_str().unwrap(),
        "--output",
        directory.path().join("out").to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 0);
    assert_eq!(response["data"]["skipped_count"], 1);
    assert!(
        response["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| { warning["code"] == "document_skipped_encrypted" })
    );
}

#[test]
fn all_commands_have_human_output_with_explicit_verification_boundaries() {
    for (command, expected) in [
        ("inspect", "not verified"),
        ("list", "none were verified"),
        ("validate-structure", "verification was not performed"),
    ] {
        let output = run(&[command, fixture("plain-base64.es3").to_str().unwrap()]);
        assert!(output.status.success(), "{command} should succeed");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(expected));
        assert!(!stdout.contains("signature is valid"));
    }

    let directory = tempdir().unwrap();
    let output_dir = directory.path().join("human-extract");
    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Extracted 1 document(s).")
    );
    assert_eq!(
        std::fs::read(output_dir.join("hello.txt")).unwrap(),
        b"Hello from openSzigno synthetic fixture.\n"
    );
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_output_directories() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    let real = directory.path().join("real");
    let linked = directory.path().join("linked");
    std::fs::create_dir(&real).unwrap();
    symlink(&real, &linked).unwrap();

    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        linked.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        parse_json(&output)["errors"][0]["code"],
        "unsafe_output_directory"
    );
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
}
