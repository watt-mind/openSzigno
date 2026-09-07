//! Integration tests for `extract --document`, `extract --stdout`, and the
//! shared bounded reader that lets any command take its dossier from stdin.
//!
//! Everything here goes through the built binary, because the flags are part
//! of the command contract rather than of a library API.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

/// A temporary directory under a fully resolved base path.
///
/// The extractor refuses an output path that contains a symlink, and the
/// platform temporary directory is itself a symlink on some systems, so the
/// base is canonicalized first.
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

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(arguments)
        .output()
        .expect("CLI must run")
}

/// Run the CLI with `input` on its standard input.
///
/// The writer runs on its own thread and ignores write failures: a run that
/// refuses an over-cap stream stops reading and closes the pipe, which is the
/// behaviour being tested, not an error.
fn run_with_stdin(arguments: &[&str], input: Vec<u8>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI must start");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        let _ = stdin.flush();
    });
    let output = child.wait_with_output().expect("CLI must terminate");
    let _ = writer.join();
    output
}

fn parse_json(output: &Output) -> Value {
    assert!(output.stderr.is_empty(), "JSON mode must keep stderr quiet");
    serde_json::from_slice(&output.stdout).expect("stdout must be exactly one JSON value")
}

fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).expect("the fixture is readable")
}

const FIRST: &[u8] = b"First synthetic payload.\n";
const SECOND: &[u8] = b"Second synthetic payload.\n";

#[test]
fn a_selector_names_one_document_by_object_ref_or_by_index() {
    let directory = scratch();

    let by_reference = directory.path().join("by-reference");
    let output = run(&[
        "extract",
        fixture("two-documents.es3").to_str().unwrap(),
        "--document",
        "DocumentObjectB",
        "--output",
        by_reference.to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 1);
    assert_eq!(response["data"]["selected"][0]["index"], 1);
    assert_eq!(
        response["data"]["selected"][0]["object_ref"],
        "DocumentObjectB"
    );
    assert_eq!(response["data"]["selected"].as_array().unwrap().len(), 1);
    assert_eq!(
        std::fs::read(by_reference.join("second.txt")).unwrap(),
        SECOND
    );
    assert!(!by_reference.join("first.txt").exists());

    let by_index = directory.path().join("by-index");
    let output = run(&[
        "extract",
        fixture("two-documents.es3").to_str().unwrap(),
        "--document",
        "#0",
        "--output",
        by_index.to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(
        response["data"]["selected"][0]["object_ref"],
        "DocumentObjectA"
    );
    assert_eq!(std::fs::read(by_index.join("first.txt")).unwrap(), FIRST);
    assert!(!by_index.join("second.txt").exists());
}

/// Repeating a selector, or naming the same document twice by two spellings,
/// extracts it once and reports it once, in source order.
#[test]
fn a_repeated_selector_selects_one_document_once() {
    let directory = scratch();
    let output_dir = directory.path().join("out");
    let output = run(&[
        "extract",
        fixture("two-documents.es3").to_str().unwrap(),
        "--document",
        "DocumentObjectB",
        "--document",
        "#1",
        "--document",
        "#0",
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);

    assert!(output.status.success());
    let selected = parse_json(&output);
    let selected = selected["data"]["selected"].as_array().unwrap().clone();
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0]["index"], 0, "the selection is in source order");
    assert_eq!(selected[1]["index"], 1);
}

/// Without `--document` the field is present and null, so a consumer can tell
/// "everything" apart from "these".
#[test]
fn an_unselected_run_reports_a_null_selection() {
    let directory = scratch();
    let output = run(&[
        "extract",
        fixture("two-documents.es3").to_str().unwrap(),
        "--output",
        directory.path().join("out").to_str().unwrap(),
        "--json",
    ]);

    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 2);
    assert_eq!(response["data"]["selected"], Value::Null);
}

#[test]
fn a_selector_that_matches_nothing_is_document_not_found() {
    let directory = scratch();
    for selector in ["#9", "NoSuchObject", "#not-a-number"] {
        let output = run(&[
            "extract",
            fixture("two-documents.es3").to_str().unwrap(),
            "--document",
            selector,
            "--output",
            directory
                .path()
                .join(selector.replace(['#'], "x"))
                .to_str()
                .unwrap(),
            "--json",
        ]);

        assert_eq!(output.status.code(), Some(4), "{selector} must be rejected");
        assert_eq!(
            parse_json(&output)["errors"][0]["code"],
            "document_not_found"
        );
    }
}

/// A `dossier_path` like `2/0` names a document inside an embedded dossier,
/// which the flag deliberately cannot reach; the message says what to do
/// instead.
#[test]
fn a_selector_never_reaches_into_an_embedded_dossier() {
    let directory = scratch();
    let output = run(&[
        "extract",
        fixture("nested-dossier.es3").to_str().unwrap(),
        "--document",
        "0/0",
        "--output",
        directory.path().join("out").to_str().unwrap(),
        "--json",
    ]);

    assert_eq!(output.status.code(), Some(4));
    let response = parse_json(&output);
    assert_eq!(response["errors"][0]["code"], "document_not_found");
    assert!(
        response["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("embedded dossier")
    );
}

/// Selecting the document that carries an embedded dossier expands it exactly
/// as an unselected run would.
#[test]
fn a_selected_embedded_dossier_still_recurses() {
    let directory = scratch();
    let output_dir = directory.path().join("out");
    let output = run(&[
        "extract",
        fixture("nested-dossier.es3").to_str().unwrap(),
        "--document",
        "#0",
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);

    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["nested_dossiers_extracted"], 1);
    assert_eq!(response["data"]["extracted_count"], 2);
    assert!(output_dir.join("court.dosszie").is_file());
    assert!(
        output_dir.join("court.dosszie.d/inner.txt").is_file(),
        "recursion applies to a selected document unchanged"
    );
}

/// A document left out by the selection was never asked for, so it is not a
/// skip; only a selected document the tool cannot decode counts.
#[test]
fn skipped_count_counts_only_the_selection() {
    let directory = scratch();
    let output = run(&[
        "extract",
        fixture("encrypted.es3").to_str().unwrap(),
        "--document",
        "#0",
        "--output",
        directory.path().join("out").to_str().unwrap(),
        "--json",
    ]);

    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 0);
    assert_eq!(response["data"]["skipped_count"], 1);

    let unselected = run(&[
        "extract",
        fixture("two-documents.es3").to_str().unwrap(),
        "--document",
        "#0",
        "--output",
        directory.path().join("other").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        parse_json(&unselected)["data"]["skipped_count"],
        0,
        "the document that was not selected is not a skip"
    );
}

#[test]
fn stdout_writes_the_payload_byte_exactly_for_plain_and_zip() {
    let plain = run(&[
        "extract",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--stdout",
    ]);
    assert!(plain.status.success());
    assert_eq!(plain.stdout, b"Hello from openSzigno synthetic fixture.\n");

    let zip = run(&[
        "extract",
        fixture("zip-base64.es3").to_str().unwrap(),
        "--stdout",
    ]);
    assert!(zip.status.success());
    assert_eq!(zip.stdout, b"Zipped openSzigno synthetic fixture.\n");

    let selected = run(&[
        "extract",
        fixture("two-documents.es3").to_str().unwrap(),
        "--document",
        "DocumentObjectB",
        "--stdout",
    ]);
    assert!(selected.status.success());
    assert_eq!(selected.stdout, SECOND);
}

/// Payload mode writes nothing but the payload, so a dossier that would emit a
/// warning emits it on stderr.
#[test]
fn payload_mode_keeps_diagnostics_off_stdout() {
    let output = run(&[
        "extract",
        fixture("compatible-namespace.es3").to_str().unwrap(),
        "--document",
        "#0",
        "--stdout",
    ]);

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning ["),
        "diagnostics belong on stderr: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("warning ["),
        "stdout carries the payload only"
    );
}

#[test]
fn stdout_is_refused_when_more_than_one_document_is_in_scope() {
    let input = fixture("two-documents.es3");
    for selectors in [vec![], vec!["--document", "#0", "--document", "#1"]] {
        let mut arguments = vec!["extract", input.to_str().unwrap(), "--stdout"];
        arguments.extend(selectors.iter().copied());
        let output = run(&arguments);

        assert_eq!(output.status.code(), Some(4));
        assert!(output.stdout.is_empty(), "no payload may be written");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("stdout_requires_single_document")
        );
    }
}

/// An embedded dossier would become a payload file *and* a `<file>.d`
/// directory; one byte stream cannot carry both, so recursion must be turned
/// off explicitly.
#[test]
fn stdout_is_refused_for_a_nested_dossier_unless_recursion_is_off() {
    let refused = run(&[
        "extract",
        fixture("nested-dossier.es3").to_str().unwrap(),
        "--stdout",
    ]);
    assert_eq!(refused.status.code(), Some(4));
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("stdout_requires_single_document"));

    let raw = run(&[
        "extract",
        fixture("nested-dossier.es3").to_str().unwrap(),
        "--stdout",
        "--no-recursive",
    ]);
    assert!(raw.status.success());
    assert!(raw.stdout.starts_with(b"<?xml version=\"1.0\""));
}

#[test]
fn stdout_is_refused_for_an_undecodable_document() {
    let output = run(&[
        "extract",
        fixture("encrypted.es3").to_str().unwrap(),
        "--stdout",
    ]);

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("document_not_extractable"));
}

#[test]
fn stdout_conflicts_with_output_and_with_json() {
    let directory = scratch();
    let input = fixture("plain-base64.es3");
    let out = directory.path().join("out");
    for extra in [vec!["--output", out.to_str().unwrap()], vec!["--json"]] {
        let mut arguments = vec!["extract", input.to_str().unwrap(), "--stdout"];
        arguments.extend(extra.iter().copied());
        let output = run(&arguments);

        assert_eq!(
            output.status.code(),
            Some(2),
            "{arguments:?} is a usage error"
        );
    }

    // And without either, `--output` is still required.
    let missing = run(&["extract", input.to_str().unwrap()]);
    assert_eq!(missing.status.code(), Some(2));
}

#[test]
fn a_closed_stdout_in_payload_mode_is_an_io_failure() {
    let (reader, writer) = std::io::pipe().expect("pipe is available");
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args([
            "extract",
            fixture("plain-base64.es3").to_str().unwrap(),
            "--stdout",
        ])
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI must start")
        .wait_with_output()
        .expect("CLI must terminate");

    assert_eq!(output.status.code(), Some(3));
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("panicked"),
        "the CLI must not panic"
    );
}

#[test]
fn every_command_reads_the_dossier_from_stdin() {
    let bytes = read_fixture("plain-base64.es3");
    for command in ["inspect", "list", "validate-structure", "verify"] {
        let output = run_with_stdin(&[command, "-", "--json"], bytes.clone());

        assert!(
            matches!(output.status.code(), Some(0 | 7)),
            "{command} from stdin must complete: {:?}",
            output.status.code()
        );
        let response = parse_json(&output);
        assert_eq!(response["command"], command);
        assert_eq!(response["input"]["format"], "microsec-es3");
        assert_eq!(response["input"]["bytes"], bytes.len());
    }
}

#[test]
fn extract_reads_the_dossier_from_stdin() {
    let directory = scratch();
    let output_dir = directory.path().join("out");
    let output = run_with_stdin(
        &[
            "extract",
            "-",
            "--output",
            output_dir.to_str().unwrap(),
            "--json",
        ],
        read_fixture("plain-base64.es3"),
    );

    assert!(output.status.success());
    assert_eq!(parse_json(&output)["data"]["extracted_count"], 1);
    assert_eq!(
        std::fs::read(output_dir.join("hello.txt")).unwrap(),
        b"Hello from openSzigno synthetic fixture.\n"
    );

    // stdin and stdout are independent streams, so `-` and `--stdout` combine.
    let piped = run_with_stdin(
        &["extract", "-", "--document", "#0", "--stdout"],
        read_fixture("plain-base64.es3"),
    );
    assert!(piped.status.success());
    assert_eq!(piped.stdout, b"Hello from openSzigno synthetic fixture.\n");
}

/// The cap holds on a stream that has no filesystem metadata to consult.
#[test]
fn an_over_cap_stdin_stream_is_input_too_large() {
    // One byte past `max_input_bytes`, so the reader's bounded read is what
    // stops it rather than any declared size.
    let oversized = vec![b' '; 64 * 1024 * 1024 + 1];
    let output = run_with_stdin(&["inspect", "-", "--json"], oversized);

    assert_eq!(output.status.code(), Some(4));
    let response = parse_json(&output);
    assert_eq!(response["errors"][0]["code"], "input_too_large");
    assert_eq!(
        response["input"]["bytes"],
        Value::Null,
        "the true size of a refused stream is unknown"
    );
}

#[test]
fn a_stdin_stream_that_is_not_a_dossier_is_a_structural_failure() {
    let output = run_with_stdin(&["inspect", "-", "--json"], b"not xml at all".to_vec());

    assert_eq!(output.status.code(), Some(4));
    let response = parse_json(&output);
    assert_eq!(response["input"]["format"], Value::Null);
    assert_eq!(response["input"]["bytes"], 14);
}
