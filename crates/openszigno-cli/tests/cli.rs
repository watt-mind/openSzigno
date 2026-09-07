use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::{TempDir, tempdir};

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

#[cfg(unix)]
#[test]
fn rejects_symlinked_intermediate_output_components() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
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
    let directory = tempdir().expect("temporary directory is available");
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
fn rejects_titles_that_differ_only_by_unicode_composition() {
    // U+00E9 versus "e" + U+0301: the same filename on any normalising or
    // case-folding filesystem.
    let (output, _directory, output_dir) =
        extract_titles(&["\u{e9}rte\u{301}s.txt", "e\u{301}rte\u{301}s.txt"]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        parse_json(&output)["errors"][0]["code"],
        "output_name_collision"
    );
    assert_eq!(count_entries(&output_dir), 0, "no file may be written");
}

#[cfg(unix)]
#[test]
fn extracted_files_are_private_to_the_user() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
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

#[test]
fn a_closed_stdout_is_an_io_failure_not_a_panic() {
    use std::process::Stdio;

    let directory = tempdir().unwrap();
    // The response must be larger than a pipe buffer, so the write cannot
    // complete before the reader goes away.
    let titles: Vec<String> = (0..250)
        .map(|index| format!("document{index:04}-{}.txt", "x".repeat(120)))
        .collect();
    let input = write_dossier(directory.path(), &titles);

    let mut child = Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(["list", input.to_str().unwrap(), "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI must start");
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("CLI must terminate");

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
