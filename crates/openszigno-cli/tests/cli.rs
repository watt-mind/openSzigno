use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::TempDir;

/// A temporary directory under a fully resolved base path.
///
/// The extractor refuses an output path that contains a symlink, and the
/// platform temporary directory is itself a symlink on some systems (macOS
/// resolves `/var` to `/private/var`), so the base is canonicalized first.
fn scratch() -> TempDir {
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory must resolve");
    tempfile::tempdir_in(base).expect("a temporary directory must be available")
}

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
    let directory = scratch();
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

    let directory = scratch();
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
    let directory = scratch();
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

    let directory = scratch();
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

    let directory = scratch();
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

#[cfg(unix)]
#[test]
fn rejects_symlinked_intermediate_output_components() {
    use std::os::unix::fs::symlink;

    let directory = scratch();
    let real = directory.path().join("real");
    let linked = directory.path().join("linked");
    std::fs::create_dir(&real).unwrap();
    symlink(&real, &linked).unwrap();
    let nested = linked.join("nested").join("out");

    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        nested.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        parse_json(&output)["errors"][0]["code"],
        "unsafe_output_directory"
    );
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
}

/// Build a dossier whose documents carry the given titles, reusing the plain
/// Base64 fixture so payload and `SourceSize` stay consistent.
fn dossier_with_titles(titles: &[String]) -> String {
    let base = std::fs::read_to_string(fixture("plain-base64.es3")).expect("fixture is readable");
    let start = base.find("<es:Document>").expect("fixture has a document");
    let end = base.find("</es:Document>").expect("fixture has a document") + "</es:Document>".len();
    let block = &base[start..end];

    let mut documents = String::new();
    for (position, title) in titles.iter().enumerate() {
        let document = block
            .replace(
                "<es:Title>hello.txt</es:Title>",
                &format!("<es:Title>{title}</es:Title>"),
            )
            .replace("DocumentProfile1", &format!("DocumentProfile{position}"))
            .replace("DocumentObject1", &format!("DocumentObject{position}"));
        documents.push_str(&document);
        documents.push('\n');
    }
    format!("{}{}{}", &base[..start], documents, &base[end..])
}

fn write_dossier(directory: &Path, titles: &[String]) -> PathBuf {
    let path = directory.join("synthetic.es3");
    std::fs::write(&path, dossier_with_titles(titles)).expect("synthetic dossier is writable");
    path
}

/// Count regular directory entries, treating a missing directory as empty.
fn count_entries(directory: &Path) -> usize {
    std::fs::read_dir(directory).map_or(0, Iterator::count)
}

fn extract_titles(titles: &[&str]) -> (Output, TempDir, PathBuf) {
    let directory = scratch();
    let owned: Vec<String> = titles.iter().map(|title| (*title).to_owned()).collect();
    let input = write_dossier(directory.path(), &owned);
    let output_dir = directory.path().join("out");
    let output = run(&[
        "extract",
        input.to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    (output, directory, output_dir)
}

#[test]
fn rejects_titles_that_hide_or_spoof_their_name() {
    for title in [
        ".hidden.txt",
        "-rf.txt",
        "invoice\u{202E}txt.exe",
        "wide\u{00A0}space.txt",
        "zero\u{200B}width.txt",
        "private\u{E000}use.txt",
    ] {
        let (output, _directory, output_dir) = extract_titles(&[title]);
        assert_eq!(output.status.code(), Some(5), "title must be rejected");
        assert_eq!(
            parse_json(&output)["errors"][0]["code"],
            "unsafe_output_name"
        );
        assert_eq!(
            count_entries(&output_dir),
            0,
            "no file may be written for a rejected title"
        );
    }
}

#[test]
fn titles_that_differ_only_by_unicode_composition_are_deduplicated() {
    // U+00E9 versus "e" + U+0301: the same filename on any normalising or
    // case-folding filesystem, so the second one is renamed rather than
    // silently written over the first.
    let (output, _directory, output_dir) =
        extract_titles(&["\u{e9}rte\u{301}s.txt", "e\u{301}rte\u{301}s.txt"]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 2);
    assert!(warning_codes(&response).contains(&"output_name_deduplicated".to_owned()));
    assert!(output_dir.join("\u{e9}rt\u{e9}s.txt").is_file());
    assert!(output_dir.join("\u{e9}rt\u{e9}s-1.txt").is_file());
    assert_eq!(count_entries(&output_dir), 2);
}

#[cfg(unix)]
#[test]
fn extracted_files_are_private_to_the_user() {
    use std::os::unix::fs::PermissionsExt;

    let directory = scratch();
    let output_dir = directory.path().join("modes");
    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    let mode = std::fs::metadata(output_dir.join("hello.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "extracted files must be user-only");
    let directory_mode = std::fs::metadata(&output_dir).unwrap().permissions().mode();
    assert_eq!(
        directory_mode & 0o777,
        0o700,
        "a directory we create must be user-only"
    );
}

/// Run the CLI with a stdout whose read end is already closed.
///
/// Closing the reader *before* the process starts is what makes this
/// deterministic: with a piped stdout that is dropped afterwards, a small
/// response can land in the pipe buffer and succeed before the reader goes
/// away.
fn run_with_closed_stdout(arguments: &[&str]) -> Output {
    use std::process::Stdio;

    let (reader, writer) = std::io::pipe().expect("pipe is available");
    drop(reader);
    Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(arguments)
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI must start")
        .wait_with_output()
        .expect("CLI must terminate")
}

#[test]
fn a_closed_stdout_is_an_io_failure_not_a_panic() {
    let directory = scratch();
    let titles: Vec<String> = (0..250)
        .map(|index| format!("document{index:04}-{}.txt", "x".repeat(120)))
        .collect();
    let input = write_dossier(directory.path(), &titles);

    let output = run_with_closed_stdout(&["list", input.to_str().unwrap(), "--json"]);

    assert_eq!(
        output.status.code(),
        Some(3),
        "a closed stdout must be reported as an I/O failure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "the CLI must not panic");
}

#[test]
fn json_mode_reports_usage_errors_in_the_envelope() {
    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let response = parse_json(&output);
    assert_eq!(response["schema_version"], 1);
    assert_eq!(response["ok"], false);
    assert_eq!(response["command"], "usage");
    assert_eq!(response["input"]["format"], Value::Null);
    assert_eq!(response["input"]["bytes"], Value::Null);
    assert_eq!(response["errors"][0]["code"], "usage_error");
}

// ---------------------------------------------------------------------------
// Synthetic dossier construction
//
// Everything below builds unsigned dossiers from scratch inside the test's own
// temporary directory; no real dossier is ever involved.
// ---------------------------------------------------------------------------

/// Render one `<es:Document>` block with fully controllable metadata.
fn document_block(
    index: usize,
    title: &str,
    extension: Option<&str>,
    source_size: u64,
    transforms: &[&str],
    payload: &str,
) -> String {
    let extension = extension.map_or_else(String::new, |value| format!(" extension=\"{value}\""));
    let transforms: String = transforms
        .iter()
        .map(|algorithm| format!("<es:Transform Algorithm=\"{algorithm}\"/>"))
        .collect();
    format!(
        "<es:Document><es:DocumentProfile Id=\"DocumentProfile{index}\" \
         OBJREF=\"DocumentObject{index}\"><es:Title>{title}</es:Title>\
         <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>\
         <es:Format><es:MIME-Type type=\"text\" subtype=\"plain\"{extension}/></es:Format>\
         <es:SourceSize sizeValue=\"{source_size}\" sizeUnit=\"B\"/>\
         <es:BaseTransform>{transforms}</es:BaseTransform></es:DocumentProfile>\
         <ds:Object Id=\"DocumentObject{index}\">{payload}</ds:Object></es:Document>"
    )
}

/// Wrap rendered document blocks in a minimal valid dossier.
fn dossier(documents: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<es:DossierProfile Id="DossierProfile1" OBJREF="Object0"><es:Title>Unsigned synthetic fixture</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate></es:DossierProfile>
<es:Documents Id="Object0">{documents}</es:Documents>
</es:Dossier>"#
    )
}

/// A one-document dossier carrying `contents` under the `base64` transform.
fn base64_document(index: usize, title: &str, extension: Option<&str>, contents: &str) -> String {
    let payload = base64_of(contents.as_bytes());
    document_block(
        index,
        title,
        extension,
        contents.len() as u64,
        &["base64"],
        &payload,
    )
}

/// Minimal standard Base64 encoder, so the test suite does not depend on the
/// encoder the CLI itself uses.
fn base64_of(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from(buffer[0]) << 16 | u32::from(buffer[1]) << 8 | u32::from(buffer[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                let position = (bits >> (18 - 6 * index)) & 0x3F;
                encoded.push(char::from(ALPHABET[position as usize]));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// Write a dossier next to the test's temporary directory and return its path.
fn write_input(directory: &Path, xml: &str) -> PathBuf {
    let path = directory.join("synthetic.es3");
    std::fs::write(&path, xml).expect("synthetic dossier is writable");
    path
}

/// Run `extract` on a dossier built from `documents` and return the response
/// together with the (still existing) temporary directory and output path.
fn extract_documents(documents: &str) -> (Output, TempDir, PathBuf) {
    let directory = scratch();
    let input = write_input(directory.path(), &dossier(documents));
    let output_dir = directory.path().join("out");
    let output = run(&[
        "extract",
        input.to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    (output, directory, output_dir)
}

fn warning_codes(response: &Value) -> Vec<String> {
    response["warnings"]
        .as_array()
        .expect("warnings must be an array")
        .iter()
        .map(|warning| warning["code"].as_str().unwrap_or_default().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// JSON envelope
// ---------------------------------------------------------------------------

#[test]
fn every_command_emits_the_same_envelope_keys() {
    let directory = scratch();
    let input = fixture("plain-base64.es3");
    let input = input.to_str().unwrap();
    let output_dir = directory.path().join("envelope");
    let commands: [(&str, Vec<&str>); 4] = [
        ("inspect", vec!["inspect", input, "--json"]),
        ("list", vec!["list", input, "--json"]),
        (
            "extract",
            vec![
                "extract",
                input,
                "--output",
                output_dir.to_str().unwrap(),
                "--json",
            ],
        ),
        (
            "validate-structure",
            vec!["validate-structure", input, "--json"],
        ),
    ];

    for (name, arguments) in commands {
        let output = run(&arguments);
        assert!(output.status.success(), "{name} must succeed");
        let response = parse_json(&output);
        let keys: Vec<&str> = response
            .as_object()
            .expect("the envelope is an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "command",
                "data",
                "errors",
                "input",
                "ok",
                "schema_version",
                "warnings"
            ],
            "{name} must emit every envelope key"
        );
        assert_eq!(response["schema_version"], 1);
        assert_eq!(response["ok"], true);
        assert_eq!(response["command"], name);
        assert_eq!(response["input"]["format"], "microsec-es3");
        assert!(response["input"]["bytes"].as_u64().unwrap() > 0);
        assert!(response["data"].is_object());
        assert_eq!(response["errors"], Value::Array(Vec::new()));
    }
}

#[test]
fn a_failed_command_reports_a_null_payload_and_one_error() {
    let output = run(&[
        "list",
        fixture("duplicate-id.es3").to_str().unwrap(),
        "--json",
    ]);
    let response = parse_json(&output);
    assert_eq!(response["ok"], false);
    assert_eq!(response["command"], "list");
    assert_eq!(response["data"], Value::Null);
    assert_eq!(response["warnings"], Value::Array(Vec::new()));
    assert_eq!(response["errors"].as_array().unwrap().len(), 1);
    assert!(
        !response["errors"][0]["message"]
            .as_str()
            .expect("a message is present")
            .is_empty()
    );
}

#[test]
fn inspect_reports_the_limits_and_the_missing_capabilities() {
    let output = run(&[
        "inspect",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--json",
    ]);
    let response = parse_json(&output);
    assert_eq!(
        response["data"]["limits"],
        serde_json::json!({
            "max_input_bytes": 67_108_864u64,
            "max_documents": 256,
            "max_base64_chars": 100_663_296u64,
            "max_decoded_document_bytes": 67_108_864u64,
            "max_total_decoded_bytes": 268_435_456u64,
            "max_zip_members": 16,
            "max_zip_expanded_bytes": 67_108_864u64,
            "max_zip_compression_ratio": 100,
            "max_xml_depth": 128,
            "max_xml_nodes": 1_000_000
        })
    );
    assert_eq!(
        response["data"]["capabilities"],
        serde_json::json!({
            "structural_validation": true,
            "base64_extraction": true,
            "zip_base64_extraction": true,
            "encrypted_extraction": "with_key",
            "cryptographic_verification": false
        })
    );
    let dossier = &response["data"]["dossier"];
    assert_eq!(dossier["title"], "Unsigned synthetic plain fixture");
    assert_eq!(dossier["category"], "electronic dossier");
    assert_eq!(
        dossier["namespace"],
        "https://www.microsec.hu/ds/e-szigno30#"
    );
    assert_eq!(dossier["xml_encoding"], "UTF-8");
    assert_eq!(dossier["documents"], 1);
    assert_eq!(dossier["signatures_present"], 0);
    assert_eq!(dossier["timestamps_present"], 0);
    assert_eq!(dossier["signatures_verified"], false);
}

#[test]
fn list_reports_document_metadata_in_source_order_without_payloads() {
    let documents = format!(
        "{}{}",
        base64_document(0, "first.txt", Some("txt"), "first"),
        base64_document(1, "second.txt", Some("txt"), "second"),
    );
    let directory = scratch();
    let input = write_input(directory.path(), &dossier(&documents));
    let response = parse_json(&run(&["list", input.to_str().unwrap(), "--json"]));

    let listed = response["data"]["documents"]
        .as_array()
        .expect("documents are listed");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0]["index"], 0);
    assert_eq!(listed[0]["title"], "first.txt");
    assert_eq!(listed[0]["source_size"], 5);
    assert_eq!(listed[0]["object_ref"], "DocumentObject0");
    assert_eq!(listed[0]["transforms"], serde_json::json!(["base64"]));
    assert_eq!(listed[1]["title"], "second.txt");
    assert!(
        listed[0].get("payload").is_none(),
        "payload bytes must never reach the protocol"
    );
    assert!(
        !String::from_utf8_lossy(&run(&["list", input.to_str().unwrap(), "--json"]).stdout)
            .contains("Zmlyc3Q="),
        "the encoded payload must not appear in the output"
    );
}

#[test]
fn validate_structure_states_that_no_signature_was_checked() {
    let response = parse_json(&run(&[
        "validate-structure",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(response["data"]["valid_structure"], true);
    assert_eq!(response["data"]["documents"], 1);
    assert_eq!(
        response["data"]["cryptographic_verification_performed"],
        false
    );
}

#[test]
fn extract_reports_what_it_wrote_and_what_it_skipped() {
    let documents = format!(
        "{}{}",
        base64_document(0, "kept.txt", Some("txt"), "kept bytes"),
        document_block(1, "skipped.bin", Some("bin"), 1, &["gzip"], "eA=="),
    );
    let (output, _directory, output_dir) = extract_documents(&documents);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 1);
    assert_eq!(response["data"]["skipped_count"], 1);
    assert_eq!(
        response["data"]["extracted"],
        serde_json::json!([{
            "document_index": 0,
            "dossier_path": "0",
            "filename": "kept.txt",
            "path": "kept.txt",
            "bytes": 10,
            "detected_type": "text",
            "declared_type": "text/plain",
            "decrypted": false
        }])
    );
    assert_eq!(response["data"]["nested_dossiers_extracted"], 0);
    assert_eq!(
        std::fs::read(output_dir.join("kept.txt")).unwrap(),
        b"kept bytes"
    );
    assert_eq!(
        count_entries(&output_dir),
        1,
        "a skipped document must not be written"
    );
    assert!(
        warning_codes(&response).contains(&"document_skipped_unsupported_transform".to_owned())
    );
}

// ---------------------------------------------------------------------------
// Human output
// ---------------------------------------------------------------------------

#[test]
fn human_inspect_output_names_the_format_and_the_unverified_material() {
    let output = run(&["inspect", fixture("plain-base64.es3").to_str().unwrap()]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("Microsec e-Szigno dossier\n"));
    assert!(stdout.contains("Title: Unsigned synthetic plain fixture\n"));
    assert!(stdout.contains("Documents: 1\n"));
    assert!(stdout.contains("Signatures present: 0 (not verified)\n"));
    assert!(stdout.contains("Timestamps present: 0 (not verified)\n"));
    assert!(!stdout.to_lowercase().contains("signature is valid"));
    assert!(!stdout.to_lowercase().contains("valid signature"));
}

#[test]
fn human_list_output_describes_every_document() {
    let output = run(&["list", fixture("plain-base64.es3").to_str().unwrap()]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("Unsigned synthetic plain fixture\n"));
    assert!(stdout.contains("[0] hello.txt | text/plain | 41 B | [\"base64\"]\n"));
    assert!(
        stdout
            .ends_with("Signatures/timestamps are listed by presence only; none were verified.\n")
    );
}

#[test]
fn human_extract_output_lists_each_written_file() {
    let directory = scratch();
    let output_dir = directory.path().join("human");
    let output = run(&[
        "extract",
        fixture("zip-base64.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Extracted 1 document(s).\n"));
    assert!(stdout.contains("[0] zipped.txt (37 B, text)\n"));
    assert!(stdout.contains("Extraction is not proof of signature validity.\n"));
}

#[test]
fn human_mode_reports_failures_on_stderr_with_a_stable_code() {
    let output = run(&["list", fixture("duplicate-id.es3").to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty(), "a failure prints no result");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("error [duplicate_id]: "));
    assert!(
        !stderr.contains("duplicate-id.es3"),
        "no path may be echoed"
    );
}

#[test]
fn human_mode_reports_warnings_on_stderr() {
    let directory = scratch();
    let output = run(&[
        "extract",
        fixture("encrypted.es3").to_str().unwrap(),
        "--output",
        directory.path().join("out").to_str().unwrap(),
    ]);
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("warning [encrypted_document_unsupported]:"));
    assert!(stderr.contains("warning [document_skipped_encrypted]:"));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Extracted 0 document(s).")
    );
}

// ---------------------------------------------------------------------------
// Capability warnings
// ---------------------------------------------------------------------------

#[test]
fn an_unsupported_transform_chain_is_reported_by_every_reading_command() {
    let directory = scratch();
    let input = write_input(
        directory.path(),
        &dossier(&document_block(
            0,
            "packed.bin",
            Some("bin"),
            1,
            &["gzip", "base64"],
            "eA==",
        )),
    );
    for command in ["inspect", "list", "validate-structure"] {
        let response = parse_json(&run(&[command, input.to_str().unwrap(), "--json"]));
        assert_eq!(response["ok"], true, "{command} still succeeds");
        assert_eq!(
            warning_codes(&response),
            ["unsupported_transform_chain"],
            "{command} must warn about the chain"
        );
    }
}

#[test]
fn an_encrypted_document_is_reported_by_every_reading_command() {
    for command in ["inspect", "list", "validate-structure"] {
        let response = parse_json(&run(&[
            command,
            fixture("encrypted.es3").to_str().unwrap(),
            "--json",
        ]));
        assert_eq!(warning_codes(&response), ["encrypted_document_unsupported"]);
    }
}

#[test]
fn signature_material_is_counted_and_flagged_as_unverified() {
    let directory = scratch();
    let xml = dossier(&base64_document(0, "signed.txt", Some("txt"), "body")).replace(
        "</es:Documents>",
        "</es:Documents><ds:Signature Id=\"Signature1\"/><es:TimeStamp Id=\"TimeStamp1\"/>",
    );
    let input = write_input(directory.path(), &xml);
    let response = parse_json(&run(&["inspect", input.to_str().unwrap(), "--json"]));
    assert_eq!(response["data"]["dossier"]["signatures_present"], 1);
    assert_eq!(response["data"]["dossier"]["timestamps_present"], 1);
    assert_eq!(response["data"]["dossier"]["signatures_verified"], false);
    assert_eq!(
        warning_codes(&response),
        ["cryptographic_verification_not_performed"]
    );
}

// ---------------------------------------------------------------------------
// Input errors
// ---------------------------------------------------------------------------

#[test]
fn a_missing_input_file_is_an_io_error() {
    let directory = scratch();
    let missing = directory.path().join("does-not-exist.es3");
    let output = run(&["inspect", missing.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(3));
    let response = parse_json(&output);
    assert_eq!(response["errors"][0]["code"], "io_error");
    assert_eq!(response["input"]["format"], Value::Null);
    assert_eq!(response["input"]["bytes"], Value::Null);
    assert!(
        !response["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("does-not-exist"),
        "the message must not echo the path"
    );
}

#[test]
fn a_directory_as_input_is_an_io_error() {
    let directory = scratch();
    let output = run(&["list", directory.path().to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(3));
    let response = parse_json(&output);
    assert_eq!(response["errors"][0]["code"], "io_error");
    assert_eq!(response["input"]["format"], Value::Null);
    assert!(response["input"]["bytes"].as_u64().is_some());
}

#[cfg(unix)]
#[test]
fn an_unreadable_input_file_is_an_io_error() {
    use std::os::unix::fs::PermissionsExt;

    let directory = scratch();
    let input = write_input(directory.path(), &dossier(""));
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o000))
        .expect("permissions are settable");
    if std::fs::File::open(&input).is_ok() {
        // A privileged user can read the file anyway; the rule is unobservable.
        return;
    }

    let output = run(&["inspect", input.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(parse_json(&output)["errors"][0]["code"], "io_error");
}

#[test]
fn an_input_above_the_size_limit_is_rejected_before_it_is_read() {
    let directory = scratch();
    let path = directory.path().join("huge.es3");
    let file = std::fs::File::create(&path).expect("the placeholder file is creatable");
    // Sparse: the bytes are never written, so the test stays fast.
    file.set_len(64 * 1024 * 1024 + 1)
        .expect("the file can be grown");
    drop(file);

    let output = run(&["inspect", path.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(4));
    let response = parse_json(&output);
    assert_eq!(response["errors"][0]["code"], "input_too_large");
    assert_eq!(response["input"]["bytes"], 64 * 1024 * 1024 + 1);
}

// ---------------------------------------------------------------------------
// Output names and destinations
// ---------------------------------------------------------------------------

#[test]
fn a_reserved_device_name_is_never_used_as_a_filename() {
    for title in ["CON", "nul.txt", "com1.log", "LPT9.dat", "aux.txt"] {
        let (output, _directory, output_dir) =
            extract_documents(&base64_document(0, title, None, "body"));
        assert_eq!(output.status.code(), Some(5), "{title} must be rejected");
        assert_eq!(
            parse_json(&output)["errors"][0]["code"],
            "unsafe_output_name"
        );
        assert_eq!(count_entries(&output_dir), 0);
    }
}

#[test]
fn an_overlong_title_is_never_used_as_a_filename() {
    let title = "a".repeat(241);
    let (output, _directory, _output_dir) =
        extract_documents(&base64_document(0, &title, None, "body"));
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        parse_json(&output)["errors"][0]["code"],
        "unsafe_output_name"
    );
}

#[test]
fn a_title_that_only_overflows_once_the_extension_is_added_is_rejected() {
    let title = "b".repeat(240);
    let (output, _directory, _output_dir) = extract_documents(&base64_document(
        0,
        &title,
        Some("abcdefghijklmnop"),
        "body",
    ));
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        parse_json(&output)["errors"][0]["code"],
        "unsafe_output_name"
    );
}

#[test]
fn a_declared_extension_that_is_not_a_plain_suffix_is_rejected() {
    for extension in ["tar.gz", "t x", "abcdefghijklmnopq", "-", "txt/"] {
        let (output, _directory, _output_dir) =
            extract_documents(&base64_document(0, "payload", Some(extension), "body"));
        assert_eq!(
            output.status.code(),
            Some(5),
            "extension {extension} must be rejected"
        );
        assert_eq!(
            parse_json(&output)["errors"][0]["code"],
            "unsafe_output_name"
        );
    }
}

#[test]
fn a_declared_extension_is_appended_only_when_it_is_missing() {
    let documents = format!(
        "{}{}{}",
        base64_document(0, "invoice", Some("pdf"), "one"),
        base64_document(1, "report.PDF", Some("pdf"), "two"),
        base64_document(2, "notes.txt", Some("txt"), "three"),
    );
    let (output, _directory, output_dir) = extract_documents(&documents);
    assert!(output.status.success());
    let names: Vec<String> = parse_json(&output)["data"]["extracted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["filename"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["invoice.pdf", "report.PDF", "notes.txt"]);
    assert_eq!(
        std::fs::read(output_dir.join("invoice.pdf")).unwrap(),
        b"one"
    );
    assert_eq!(
        std::fs::read(output_dir.join("report.PDF")).unwrap(),
        b"two"
    );
}

#[test]
fn two_titles_differing_only_in_case_are_deduplicated() {
    let documents = format!(
        "{}{}",
        base64_document(0, "Report.txt", Some("txt"), "one"),
        base64_document(1, "report.TXT", Some("txt"), "two"),
    );
    let (output, _directory, output_dir) = extract_documents(&documents);
    assert!(output.status.success());
    let response = parse_json(&output);
    let names: Vec<&str> = response["data"]["extracted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["filename"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Report.txt", "report-1.TXT"]);
    assert_eq!(
        std::fs::read(output_dir.join("Report.txt")).unwrap(),
        b"one"
    );
    assert_eq!(
        std::fs::read(output_dir.join("report-1.TXT")).unwrap(),
        b"two"
    );
    assert_eq!(count_entries(&output_dir), 2);
}

#[test]
fn an_existing_regular_file_is_never_used_as_the_output_directory() {
    let directory = scratch();
    let blocker = directory.path().join("not-a-directory");
    std::fs::write(&blocker, b"in the way").expect("the blocker file is writable");

    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        blocker.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        parse_json(&output)["errors"][0]["code"],
        "unsafe_output_directory"
    );
    assert_eq!(
        std::fs::read(&blocker).unwrap(),
        b"in the way",
        "the blocking file must be untouched"
    );
}

#[test]
fn a_regular_file_inside_the_output_path_is_an_io_error() {
    let directory = scratch();
    let blocker = directory.path().join("file");
    std::fs::write(&blocker, b"in the way").expect("the blocker file is writable");
    let nested = blocker.join("nested");

    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        nested.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(parse_json(&output)["errors"][0]["code"], "io_error");
}

#[cfg(unix)]
#[test]
fn an_existing_symlink_destination_is_never_written_through() {
    use std::os::unix::fs::symlink;

    let directory = scratch();
    let output_dir = directory.path().join("out");
    let target = directory.path().join("target.txt");
    std::fs::create_dir(&output_dir).expect("the output directory is creatable");
    std::fs::write(&target, b"original").expect("the target file is writable");
    symlink(&target, output_dir.join("hello.txt")).expect("the symlink is creatable");

    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(parse_json(&output)["errors"][0]["code"], "output_exists");
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"original",
        "the symlink target must be untouched"
    );
}

#[cfg(unix)]
#[test]
fn an_output_path_that_cannot_be_inspected_is_an_io_error() {
    use std::os::unix::fs::PermissionsExt;

    let directory = scratch();
    let locked = directory.path().join("locked");
    std::fs::create_dir(&locked).expect("the directory is creatable");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
        .expect("permissions are settable");
    if std::fs::read_dir(locked.join("inner")).is_ok() {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).ok();
        return; // A privileged user is not blocked by the mode.
    }

    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        locked.join("inner").to_str().unwrap(),
        "--json",
    ]);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
        .expect("permissions are restorable");

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(parse_json(&output)["errors"][0]["code"], "io_error");
}

#[test]
fn extraction_creates_a_deeply_nested_output_directory() {
    let directory = scratch();
    let nested = directory.path().join("a").join("b").join("c");
    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        nested.to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    assert_eq!(
        std::fs::read(nested.join("hello.txt")).unwrap(),
        b"Hello from openSzigno synthetic fixture.\n"
    );
}

#[test]
fn a_relative_output_path_is_resolved_against_the_working_directory() {
    let directory = scratch();
    let output = Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .current_dir(directory.path())
        .args([
            "extract",
            fixture("plain-base64.es3").to_str().unwrap(),
            "--output",
            "./here/../there",
            "--json",
        ])
        .output()
        .expect("CLI must run");
    assert!(output.status.success());
    assert_eq!(
        std::fs::read(directory.path().join("there").join("hello.txt")).unwrap(),
        b"Hello from openSzigno synthetic fixture.\n"
    );
}

#[test]
fn both_payload_fixtures_extract_byte_for_byte() {
    for (name, filename, contents) in [
        (
            "plain-base64.es3",
            "hello.txt",
            &b"Hello from openSzigno synthetic fixture.\n"[..],
        ),
        (
            "zip-base64.es3",
            "zipped.txt",
            &b"Zipped openSzigno synthetic fixture.\n"[..],
        ),
    ] {
        let directory = scratch();
        let output_dir = directory.path().join("out");
        let output = run(&[
            "extract",
            fixture(name).to_str().unwrap(),
            "--output",
            output_dir.to_str().unwrap(),
            "--json",
        ]);
        assert!(output.status.success(), "{name} must extract");
        let written = std::fs::read(output_dir.join(filename)).expect("the payload is written");
        assert_eq!(written, contents, "{name} must round-trip exactly");
        assert_eq!(count_entries(&output_dir), 1);
    }
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

#[test]
fn human_usage_errors_go_to_stderr_and_exit_two() {
    for arguments in [
        vec!["extract", fixture("plain-base64.es3").to_str().unwrap()],
        vec!["explode", fixture("plain-base64.es3").to_str().unwrap()],
        vec!["inspect"],
        vec!["inspect", "--unknown-flag"],
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "usage text belongs on stderr");
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn an_unknown_subcommand_in_json_mode_is_still_one_envelope() {
    let output = run(&["explode", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let response = parse_json(&output);
    assert_eq!(response["command"], "usage");
    assert_eq!(response["errors"][0]["code"], "usage_error");
    assert_eq!(
        response["errors"][0]["message"],
        "invalid command-line usage"
    );
    assert_eq!(response["data"], Value::Null);
    assert_eq!(response["warnings"], Value::Array(Vec::new()));
}

#[test]
fn help_and_version_are_plain_text_successes() {
    for flag in ["--help", "-h"] {
        let output = run(&[flag]);
        assert!(output.status.success(), "{flag} must exit zero");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("inspect"), "{flag} must list the commands");
        assert!(stdout.contains("extract"));
    }
    assert!(
        String::from_utf8(run(&["--help"]).stdout)
            .unwrap()
            .contains("never judges legal authenticity"),
        "the long help must state the verification boundary"
    );

    for flag in ["--version", "-V"] {
        let output = run(&[flag]);
        assert!(output.status.success(), "{flag} must exit zero");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .starts_with("openszigno ")
        );
    }

    let output = run(&["extract", "--help"]);
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("--output")
    );
}

#[test]
fn help_wins_over_json_mode() {
    let output = run(&["--help", "--json"]);
    assert!(output.status.success());
    assert!(
        serde_json::from_slice::<Value>(&output.stdout).is_err(),
        "help output is plain text, not an envelope"
    );
}

#[cfg(unix)]
#[test]
fn an_output_directory_that_cannot_be_searched_is_an_io_error() {
    use std::os::unix::fs::PermissionsExt;

    let directory = scratch();
    let output_dir = directory.path().join("unsearchable");
    std::fs::create_dir(&output_dir).expect("the output directory is creatable");
    // Readable but not searchable: the destination check cannot run.
    std::fs::set_permissions(&output_dir, std::fs::Permissions::from_mode(0o400))
        .expect("permissions are settable");
    if std::fs::metadata(output_dir.join("hello.txt")).is_ok() {
        std::fs::set_permissions(&output_dir, std::fs::Permissions::from_mode(0o700)).ok();
        return; // A privileged user is not blocked by the mode.
    }

    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    std::fs::set_permissions(&output_dir, std::fs::Permissions::from_mode(0o700))
        .expect("permissions are restorable");

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(parse_json(&output)["errors"][0]["code"], "io_error");
    assert_eq!(count_entries(&output_dir), 0, "nothing may be written");
}

#[cfg(unix)]
#[test]
fn an_output_directory_that_cannot_be_written_is_an_io_error() {
    use std::os::unix::fs::PermissionsExt;

    let directory = scratch();
    let output_dir = directory.path().join("read-only");
    std::fs::create_dir(&output_dir).expect("the output directory is creatable");
    std::fs::set_permissions(&output_dir, std::fs::Permissions::from_mode(0o500))
        .expect("permissions are settable");
    if std::fs::File::create(output_dir.join("probe")).is_ok() {
        std::fs::set_permissions(&output_dir, std::fs::Permissions::from_mode(0o700)).ok();
        return; // A privileged user is not blocked by the mode.
    }

    let output = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    std::fs::set_permissions(&output_dir, std::fs::Permissions::from_mode(0o700))
        .expect("permissions are restorable");

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(parse_json(&output)["errors"][0]["code"], "io_error");
    assert_eq!(count_entries(&output_dir), 0, "nothing may be left behind");
}

#[test]
fn a_closed_stdout_is_an_io_failure_for_failures_and_usage_errors_too() {
    for arguments in [
        vec![
            "list",
            fixture("duplicate-id.es3").to_str().unwrap(),
            "--json",
        ],
        vec!["explode", "--json"],
    ] {
        let output = run_with_closed_stdout(&arguments);

        assert_eq!(
            output.status.code(),
            Some(3),
            "{arguments:?} must report a closed stdout as an I/O failure"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("panicked"),
            "the CLI must not panic"
        );
    }
}

/// A synthetic dossier with one document-level signature carrying XAdES
/// properties and evidence containers, a countersignature, and a dossier-level
/// `es:TimeStamp`. Nothing in it is real: the signature value, the
/// certificate, and the token are all the placeholder `AA==`, which is exactly
/// the point, because the inventory reports claims and verifies nothing.
const SIGNED_INVENTORY: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8"?>"#,
    r#"<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#""#,
    r#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#""#,
    r#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">"#,
    r#"<es:DossierProfile Id="DossierProfile1" OBJREF="Object0">"#,
    "<es:Title>Synthetic signed fixture</es:Title>",
    "<es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate></es:DossierProfile>",
    r#"<es:Documents Id="Object0"><es:Document>"#,
    r#"<es:DocumentProfile Id="DocumentProfile0" OBJREF="DocumentObject0">"#,
    "<es:Title>hello.txt</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>",
    r#"<es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format>"#,
    r#"<es:SourceSize sizeValue="5" sizeUnit="B"/>"#,
    r#"<es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform>"#,
    "</es:DocumentProfile>",
    r#"<ds:Object Id="DocumentObject0">aGVsbG8=</ds:Object>"#,
    r#"<ds:Signature Id="doc-sig"><ds:SignedInfo>"#,
    r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>"#,
    r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>"#,
    r##"<ds:Reference URI="#DocumentObject0">"##,
    r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
    "<ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:SignedInfo>",
    "<ds:SignatureValue>AA==</ds:SignatureValue>",
    "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>AA==</ds:X509Certificate>",
    "</ds:X509Data></ds:KeyInfo>",
    r##"<ds:Object><xades:QualifyingProperties Target="#doc-sig">"##,
    "<xades:SignedProperties><xades:SignedSignatureProperties>",
    "<xades:SigningTime>2026-01-02T03:04:05Z</xades:SigningTime>",
    "<xades:SigningCertificate><xades:Cert/></xades:SigningCertificate>",
    "</xades:SignedSignatureProperties></xades:SignedProperties>",
    "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>",
    "<xades:CertificateValues>",
    "<xades:EncapsulatedX509Certificate>AA==</xades:EncapsulatedX509Certificate>",
    "</xades:CertificateValues>",
    r#"<xades:CounterSignature><ds:Signature Id="counter-sig"><ds:SignedInfo>"#,
    r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>"#,
    r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>"#,
    r##"<ds:Reference URI="#doc-sig">"##,
    r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
    "<ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:SignedInfo>",
    "<ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature></xades:CounterSignature>",
    "</xades:UnsignedSignatureProperties></xades:UnsignedProperties>",
    "</xades:QualifyingProperties></ds:Object></ds:Signature>",
    "</es:Document></es:Documents>",
    r##"<es:TimeStamp><xades:Include URI="#DossierProfile1"/>"##,
    r##"<xades:Include URI="#Object0"/>"##,
    "<xades:EncapsulatedTimeStamp>AA==</xades:EncapsulatedTimeStamp></es:TimeStamp>",
    "</es:Dossier>",
);

/// Write the synthetic signed dossier and return the directory holding it,
/// which the caller keeps alive for as long as the path is used.
fn signed_input() -> (TempDir, PathBuf) {
    let directory = scratch();
    let path = directory.path().join("signed.es3");
    std::fs::write(&path, SIGNED_INVENTORY).expect("the fixture must be writable");
    (directory, path)
}

#[test]
fn inspect_and_list_json_carry_the_unverified_signature_inventory() {
    let (_directory, path) = signed_input();
    for command in ["inspect", "list"] {
        let output = run(&[command, path.to_str().unwrap(), "--json"]);
        assert!(output.status.success(), "{command} should succeed");
        let dossier = &parse_json(&output)["data"]["dossier"];

        assert_eq!(dossier["signatures_present"], 2, "{command}");
        assert_eq!(dossier["timestamps_present"], 1, "{command}");
        let inventory = &dossier["signature_inventory"];
        assert_eq!(
            inventory["verified"], false,
            "{command} must never present the inventory as verified"
        );

        let signature = &inventory["signatures"][0];
        assert_eq!(signature["id"], "doc-sig");
        assert_eq!(signature["placement"], "document");
        assert_eq!(signature["document_index"], 0);
        assert_eq!(signature["parent_signature_id"], Value::Null);
        assert_eq!(
            signature["canonicalization_method"],
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        );
        assert_eq!(
            signature["signature_method"],
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        );
        assert_eq!(
            signature["digest_methods"],
            json!(["http://www.w3.org/2001/04/xmlenc#sha256"])
        );
        assert_eq!(signature["reference_count"], 1);
        assert_eq!(signature["reference_uris"], json!(["#DocumentObject0"]));
        assert_eq!(
            signature["xades_namespace"],
            "http://uri.etsi.org/01903/v1.3.2#"
        );
        assert_eq!(
            signature["xades_properties"],
            json!([
                "SigningTime",
                "SigningCertificate",
                "CertificateValues",
                "CounterSignature"
            ])
        );
        assert_eq!(
            signature["evidence"],
            json!({
                "certificates": 1,
                "crls": 0,
                "ocsp_responses": 0,
                "signature_timestamps": 0,
                "archive_timestamps": 0
            })
        );
        assert_eq!(signature["claimed_signing_time"], "2026-01-02T03:04:05Z");
        assert_eq!(signature["key_info_certificates"], 1);

        let counter = &inventory["signatures"][1];
        assert_eq!(counter["placement"], "nested_in_signature");
        assert_eq!(counter["parent_signature_id"], "doc-sig");

        assert_eq!(
            inventory["timestamps"],
            json!([{
                "placement": "dossier",
                "document_index": Value::Null,
                "include_count": 2,
                "has_token": true
            }])
        );
    }
}

#[test]
fn an_unsigned_dossier_has_an_empty_inventory_in_json() {
    let output = run(&[
        "inspect",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--json",
    ]);
    let inventory = &parse_json(&output)["data"]["dossier"]["signature_inventory"];

    assert_eq!(inventory["verified"], false);
    assert_eq!(inventory["signatures"], json!([]));
    assert_eq!(inventory["timestamps"], json!([]));
}

#[test]
fn human_inspect_marks_every_inventory_line_unverified() {
    let (_directory, path) = signed_input();
    let output = run(&["inspect", path.to_str().unwrap()]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("human output is UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();

    assert_eq!(lines[3], "Signatures present: 2 (not verified)");
    assert_eq!(lines[4], "Timestamps present: 1 (not verified)");
    assert_eq!(
        lines[5],
        "Signature inventory (claimed by the dossier; nothing below was verified):"
    );
    assert_eq!(
        lines[6],
        concat!(
            "(unverified) signature 0: placement=document, document=0, id=doc-sig, ",
            "references=1, xades=SigningTime+SigningCertificate+CertificateValues+CounterSignature, ",
            "certificates=1, crls=0, ocsp=0, signature-timestamps=0, archive-timestamps=0, ",
            "claimed signing time=2026-01-02T03:04:05Z"
        )
    );
    assert_eq!(
        lines[7],
        concat!(
            "(unverified) signature 1: placement=nested_in_signature, id=counter-sig, ",
            "inside=doc-sig, references=1, certificates=0, crls=0, ocsp=0, ",
            "signature-timestamps=0, archive-timestamps=0"
        )
    );
    assert_eq!(
        lines[8],
        "(unverified) timestamp 0: placement=dossier, includes=2, token=present"
    );
    assert_eq!(lines.len(), 9);
    assert!(
        stdout.lines().skip(5).all(|line| line.starts_with("(unverified)")
            || line.starts_with("Signature inventory")),
        "no inventory line may read as a verified finding"
    );
}

#[test]
fn human_inspect_prints_no_inventory_for_an_unsigned_dossier() {
    let output = run(&["inspect", fixture("plain-base64.es3").to_str().unwrap()]);
    let stdout = String::from_utf8(output.stdout).expect("human output is UTF-8");

    assert!(!stdout.contains("Signature inventory"));
    assert!(!stdout.contains("(unverified)"));
}
