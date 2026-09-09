//! End-to-end tests for `openszigno create`: what it writes, what the other
//! commands make of it, and what it refuses.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

const CREATED: &str = "2026-01-01T00:00:00Z";

/// A temporary directory under a fully resolved base path, because the output
/// directory machinery refuses a path that contains a symlink.
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
    serde_json::from_slice(&output.stdout).expect("stdout must be exactly one JSON value")
}

fn path_of(path: &Path) -> String {
    path.to_str().expect("a UTF-8 path").to_owned()
}

/// `create` with the two committed inputs, at the pinned creation date.
fn create_two(output: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "create".to_owned(),
        "--output".to_owned(),
        path_of(output),
        "--title".to_owned(),
        "Synthetic created dossier".to_owned(),
        "--document".to_owned(),
        path_of(&fixture("create/hello.txt")),
        "--document".to_owned(),
        path_of(&fixture("create/note.txt")),
        "--created".to_owned(),
        CREATED.to_owned(),
    ];
    args.extend(extra.iter().map(|value| (*value).to_owned()));
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&borrowed)
}

#[test]
fn creates_the_committed_fixture_byte_for_byte() {
    let directory = scratch();
    let output = directory.path().join("created.es3");
    let result = create_two(&output, &["--json"]);
    assert!(result.status.success(), "create must succeed");
    assert_eq!(
        std::fs::read(&output).expect("the dossier is written"),
        std::fs::read(fixture("created.es3")).expect("the fixture is readable"),
        "create must reproduce tests/fixtures/created.es3"
    );

    let response = parse_json(&result);
    assert_eq!(response["schema_version"], 1);
    assert_eq!(response["ok"], true);
    assert_eq!(response["command"], "create");
    assert_eq!(response["input"]["format"], "microsec-es3");
    assert_eq!(response["input"]["bytes"], Value::Null);
    assert_eq!(response["errors"], Value::Array(Vec::new()));
    assert_eq!(response["warnings"][0]["code"], "created_dossier_unsigned");
    let data = &response["data"];
    assert_eq!(data["output"], path_of(&output));
    assert_eq!(data["created"], CREATED);
    assert_eq!(
        data["bytes"],
        std::fs::metadata(&output).expect("metadata").len()
    );
    let documents = data["documents"].as_array().expect("an array");
    assert_eq!(documents.len(), 2);
    assert_eq!(documents[0]["index"], 0);
    assert_eq!(documents[0]["title"], "hello.txt");
    assert_eq!(documents[0]["mime_type"]["media_type"], "text");
    assert_eq!(documents[0]["mime_type"]["subtype"], "plain");
    assert_eq!(documents[0]["mime_type"]["extension"], "txt");
    assert_eq!(documents[0]["source_size"], 54);
    assert_eq!(documents[0]["transforms"][0], "base64");
    assert_eq!(documents[0]["nested_dossier"], false);
    assert_eq!(documents[1]["title"], "note.txt");
}

#[test]
fn the_same_request_twice_produces_the_same_bytes() {
    let directory = scratch();
    let first = directory.path().join("first.es3");
    let second = directory.path().join("second.es3");
    assert!(create_two(&first, &["--zip"]).status.success());
    assert!(create_two(&second, &["--zip"]).status.success());
    assert_eq!(
        std::fs::read(&first).expect("first"),
        std::fs::read(&second).expect("second")
    );
}

#[test]
fn what_create_writes_lists_validates_and_inspects_cleanly() {
    let directory = scratch();
    let output = directory.path().join("created.es3");
    assert!(create_two(&output, &[]).status.success());
    let dossier = path_of(&output);

    let validate = run(&["validate-structure", &dossier, "--json"]);
    assert!(validate.status.success());
    let response = parse_json(&validate);
    assert_eq!(response["data"]["valid_structure"], true);
    assert_eq!(response["data"]["conformance_warnings"], 0);
    assert_eq!(response["warnings"], Value::Array(Vec::new()));

    let inspect = parse_json(&run(&["inspect", &dossier, "--json"]));
    assert_eq!(inspect["data"]["dossier"]["signatures_present"], 0);
    assert_eq!(inspect["data"]["dossier"]["timestamps_present"], 0);
    assert_eq!(
        inspect["data"]["dossier"]["title"],
        "Synthetic created dossier"
    );

    let list = parse_json(&run(&["list", &dossier, "--json"]));
    let documents = list["data"]["documents"].as_array().expect("an array");
    assert_eq!(documents.len(), 2);
    assert_eq!(documents[0]["title"], "hello.txt");
    assert_eq!(documents[0]["mime_type"]["subtype"], "plain");
    assert_eq!(documents[0]["source_size"], 54);
    assert_eq!(documents[1]["title"], "note.txt");
    assert_eq!(documents[1]["source_size"], 62);
}

/// Every input comes back byte for byte, plain and through `--zip`.
#[test]
fn extract_reproduces_every_input_byte_for_byte() {
    for zip in [&[][..], &["--zip"][..]] {
        let directory = scratch();
        let output = directory.path().join("created.es3");
        assert!(create_two(&output, zip).status.success());
        let target = directory.path().join("out");
        let extract = run(&[
            "extract",
            &path_of(&output),
            "--output",
            &path_of(&target),
            "--json",
        ]);
        assert!(extract.status.success(), "extract must succeed");
        assert_eq!(parse_json(&extract)["data"]["extracted_count"], 2);
        for name in ["hello.txt", "note.txt"] {
            assert_eq!(
                std::fs::read(target.join(name)).expect("the file is written"),
                std::fs::read(fixture(&format!("create/{name}"))).expect("the input"),
                "{name} must come back unchanged (zip: {})",
                !zip.is_empty()
            );
        }
    }
}

#[test]
fn an_embedded_dossier_is_expanded_by_extract() {
    let directory = scratch();
    let inner = directory.path().join("inner.es3");
    assert!(create_two(&inner, &[]).status.success());
    let outer = directory.path().join("outer.es3");
    let result = run(&[
        "create",
        "--output",
        &path_of(&outer),
        "--title",
        "Outer dossier",
        "--document",
        &path_of(&fixture("create/hello.txt")),
        "--embed",
        &path_of(&inner),
        "--created",
        CREATED,
        "--json",
    ]);
    assert!(result.status.success(), "create --embed must succeed");
    let documents = parse_json(&result)["data"]["documents"]
        .as_array()
        .expect("an array")
        .clone();
    assert_eq!(documents[1]["title"], "inner.dosszie");
    assert_eq!(documents[1]["nested_dossier"], true);
    assert_eq!(documents[1]["mime_type"]["subtype"], "nldossier2");

    let list = parse_json(&run(&["list", &path_of(&outer), "--json"]));
    assert_eq!(list["data"]["dossier"]["nested_dossiers"], 1);

    let target = directory.path().join("out");
    let extract = run(&[
        "extract",
        &path_of(&outer),
        "--output",
        &path_of(&target),
        "--json",
    ]);
    assert!(extract.status.success());
    assert_eq!(
        std::fs::read(target.join("inner.dosszie")).expect("the embedded dossier"),
        std::fs::read(&inner).expect("the inner dossier")
    );
    for name in ["hello.txt", "note.txt"] {
        assert_eq!(
            std::fs::read(target.join("inner.dosszie.d").join(name)).expect("an inner document"),
            std::fs::read(fixture(&format!("create/{name}"))).expect("the input")
        );
    }
}

#[test]
fn an_existing_output_is_never_overwritten() {
    let directory = scratch();
    let output = directory.path().join("created.es3");
    assert!(create_two(&output, &[]).status.success());
    let before = std::fs::read(&output).expect("the first dossier");

    let second = create_two(&output, &["--json"]);
    assert_eq!(second.status.code(), Some(5));
    let response = parse_json(&second);
    assert_eq!(response["ok"], false);
    assert_eq!(response["data"], Value::Null);
    assert_eq!(response["input"]["format"], Value::Null);
    assert_eq!(response["errors"][0]["code"], "output_exists");
    assert_eq!(
        std::fs::read(&output).expect("the dossier is untouched"),
        before
    );
}

#[test]
fn a_title_extraction_would_refuse_is_refused_and_nothing_is_written() {
    let directory = scratch();
    let output = directory.path().join("created.es3");
    let result = run(&[
        "create",
        "--output",
        &path_of(&output),
        "--title",
        "Unsafe titles",
        "--document",
        &format!("{}::../escape.txt", path_of(&fixture("create/hello.txt"))),
        "--created",
        CREATED,
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(4));
    let response = parse_json(&result);
    assert_eq!(response["errors"][0]["code"], "unsafe_document_title");
    assert!(!output.exists(), "nothing may be written after a refusal");
}

#[test]
fn a_document_whose_type_cannot_be_determined_needs_one_given() {
    let directory = scratch();
    let output = directory.path().join("created.es3");
    let source = format!("{}::payload.bin", path_of(&fixture("create/hello.txt")));
    let result = run(&[
        "create",
        "--output",
        &path_of(&output),
        "--title",
        "Unknown type",
        "--document",
        &source,
        "--created",
        CREATED,
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(4));
    assert_eq!(
        parse_json(&result)["errors"][0]["code"],
        "unknown_mime_type"
    );

    let typed = run(&[
        "create",
        "--output",
        &path_of(&output),
        "--title",
        "Explicit type",
        "--document",
        &format!("{source}::application/octet-stream"),
        "--created",
        CREATED,
        "--json",
    ]);
    assert!(typed.status.success());
    assert_eq!(
        parse_json(&typed)["data"]["documents"][0]["mime_type"]["subtype"],
        "octet-stream"
    );
}

#[test]
fn an_embed_that_is_not_a_dossier_is_refused() {
    let directory = scratch();
    let output = directory.path().join("created.es3");
    let result = run(&[
        "create",
        "--output",
        &path_of(&output),
        "--title",
        "Bad embed",
        "--embed",
        &path_of(&fixture("create/hello.txt")),
        "--created",
        CREATED,
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(4));
    assert_eq!(parse_json(&result)["errors"][0]["code"], "invalid_xml");
    assert!(!output.exists());
}

#[test]
fn usage_errors_are_reported_before_anything_runs() {
    let directory = scratch();
    let output = directory.path().join("created.es3");
    // A creation date that is not RFC 3339.
    let result = run(&[
        "create",
        "--output",
        &path_of(&output),
        "--title",
        "Bad date",
        "--document",
        &path_of(&fixture("create/hello.txt")),
        "--created",
        "yesterday",
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(2));
    let response = parse_json(&result);
    assert_eq!(response["command"], "usage");
    assert_eq!(response["errors"][0]["code"], "usage_error");
    assert!(!output.exists());

    // No document and no embedded dossier at all.
    let empty = run(&[
        "create",
        "--output",
        &path_of(&output),
        "--title",
        "Nothing to hold",
        "--created",
        CREATED,
        "--json",
    ]);
    assert_eq!(empty.status.code(), Some(4));
    assert_eq!(parse_json(&empty)["errors"][0]["code"], "no_documents");
    assert!(!output.exists());
}

#[test]
fn the_human_summary_names_the_output_and_every_document() {
    let directory = scratch();
    let output = directory.path().join("created.es3");
    let result = create_two(&output, &[]);
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).expect("UTF-8 output");
    assert!(text.starts_with(&format!("Created {} (", path_of(&output))));
    assert!(text.contains("[0] hello.txt | text/plain | 54 B | [\"base64\"]"));
    assert!(text.contains("[1] note.txt | text/plain | 62 B | [\"base64\"]"));
    assert!(text.contains("The dossier is unsigned"));
    let stderr = String::from_utf8(result.stderr).expect("UTF-8 diagnostics");
    assert!(stderr.contains("warning [created_dossier_unsigned]"));
}
