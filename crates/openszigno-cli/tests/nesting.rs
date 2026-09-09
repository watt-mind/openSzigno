//! Namespace policy, structural warnings, sniffing, and recursive extraction.
//!
//! Every input here is synthetic and unsigned, built by the test itself or
//! taken from the committed CC0 fixtures.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

const CEGELJARAS_2014: &str = "http://www.e-cegjegyzek.hu/2014/e-cegeljaras#";
const PRIVATE_NAMESPACE: &str = "https://example.invalid/private-profile#";

/// A temporary directory under a fully resolved base path; the extractor
/// refuses an output path that contains a symlink.
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

fn warning_codes(response: &Value) -> Vec<String> {
    response["warnings"]
        .as_array()
        .expect("warnings must be an array")
        .iter()
        .map(|warning| warning["code"].as_str().unwrap_or_default().to_owned())
        .collect()
}

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

/// One `<es:Document>` with caller-chosen media type, extension, and payload.
fn document(
    index: usize,
    title: &str,
    media_type: &str,
    subtype: &str,
    extension: Option<&str>,
    payload: &[u8],
) -> String {
    let extension = extension.map_or_else(String::new, |value| format!(" extension=\"{value}\""));
    format!(
        "<es:Document><es:DocumentProfile Id=\"DocumentProfile{index}\" \
         OBJREF=\"DocumentObject{index}\"><es:Title>{title}</es:Title>\
         <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>\
         <es:Format><es:MIME-Type type=\"{media_type}\" subtype=\"{subtype}\"{extension}/></es:Format>\
         <es:SourceSize sizeValue=\"{size}\" sizeUnit=\"B\"/>\
         <es:BaseTransform><es:Transform Algorithm=\"base64\"/></es:BaseTransform>\
         </es:DocumentProfile><ds:Object Id=\"DocumentObject{index}\">{encoded}</ds:Object></es:Document>",
        size = payload.len(),
        encoded = base64_of(payload),
    )
}

fn text_document(index: usize, title: &str, contents: &str) -> String {
    document(
        index,
        title,
        "text",
        "plain",
        Some("txt"),
        contents.as_bytes(),
    )
}

/// A document declaring the nested-dossier media type around `payload`.
fn nested_document(index: usize, title: &str, payload: &[u8]) -> String {
    document(
        index,
        title,
        "application",
        "nldossier2",
        Some("dosszie"),
        payload,
    )
}

fn dossier(documents: &str) -> String {
    dossier_in(documents, "https://www.microsec.hu/ds/e-szigno30#")
}

fn dossier_in(documents: &str, namespace: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<es:Dossier xmlns:es=\"{namespace}\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
<es:DossierProfile Id=\"DossierProfile1\" OBJREF=\"Object0\">\
<es:Title>Unsigned synthetic fixture</es:Title>\
<es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate></es:DossierProfile>\
<es:Documents Id=\"Object0\">{documents}</es:Documents></es:Dossier>"
    )
}

fn write_input(directory: &Path, xml: &str) -> PathBuf {
    let path = directory.join("synthetic.es3");
    std::fs::write(&path, xml).expect("synthetic dossier is writable");
    path
}

/// Run `extract --json` on one synthetic dossier with extra flags.
fn extract_with(xml: &str, flags: &[&str]) -> (Output, TempDir, PathBuf) {
    let directory = scratch();
    let input = write_input(directory.path(), xml);
    let output_dir = directory.path().join("out");
    let mut args = vec![
        "extract",
        input.to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ];
    args.extend_from_slice(flags);
    let output = run(&args);
    (output, directory, output_dir)
}

fn count_entries(directory: &Path) -> usize {
    std::fs::read_dir(directory)
        .map(|entries| entries.count())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Namespace policy
// ---------------------------------------------------------------------------

#[test]
fn a_company_court_namespace_is_accepted_by_every_command() {
    let path = fixture("compatible-namespace.es3");
    for command in ["inspect", "list", "validate-structure"] {
        let output = run(&[command, path.to_str().unwrap(), "--json"]);
        assert!(output.status.success(), "{command} must succeed");
        let response = parse_json(&output);
        assert_eq!(response["ok"], true);
        assert_eq!(
            warning_codes(&response),
            ["dangling_objref", "document_without_profile"],
            "{command} must surface both structural warnings"
        );
    }

    let response = parse_json(&run(&["inspect", path.to_str().unwrap(), "--json"]));
    assert_eq!(response["data"]["dossier"]["namespace"], CEGELJARAS_2014);
    assert_eq!(response["data"]["dossier"]["documents"], 1);
}

#[test]
fn validate_structure_counts_the_conformance_warnings() {
    let response = parse_json(&run(&[
        "validate-structure",
        fixture("compatible-namespace.es3").to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(response["data"]["valid_structure"], true);
    assert_eq!(response["data"]["conformance_warnings"], 2);
    assert_eq!(response["data"]["documents"], 1);

    let clean = parse_json(&run(&[
        "validate-structure",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(clean["data"]["conformance_warnings"], 0);
}

#[test]
fn an_unlisted_namespace_is_rejected_until_it_is_allowed() {
    let directory = scratch();
    let input = write_input(
        directory.path(),
        &dossier_in(&text_document(0, "note.txt", "hello"), PRIVATE_NAMESPACE),
    );
    for command in ["inspect", "list", "validate-structure"] {
        let rejected = run(&[command, input.to_str().unwrap(), "--json"]);
        assert_eq!(rejected.status.code(), Some(4), "{command} must reject it");
        let response = parse_json(&rejected);
        assert_eq!(response["errors"][0]["code"], "wrong_root");
        assert!(
            !response["errors"][0]["message"]
                .as_str()
                .unwrap()
                .contains(PRIVATE_NAMESPACE),
            "the namespace URI must never be echoed"
        );

        let allowed = run(&[
            command,
            input.to_str().unwrap(),
            "--json",
            "--allow-namespace",
            PRIVATE_NAMESPACE,
        ]);
        assert!(allowed.status.success(), "{command} must accept it now");
    }
}

#[test]
fn allow_namespace_is_repeatable_and_keeps_the_known_ones() {
    let directory = scratch();
    let input = write_input(
        directory.path(),
        &dossier_in(&text_document(0, "note.txt", "hello"), PRIVATE_NAMESPACE),
    );
    let response = parse_json(&run(&[
        "list",
        input.to_str().unwrap(),
        "--json",
        "--allow-namespace",
        "https://example.invalid/other#",
        "--allow-namespace",
        PRIVATE_NAMESPACE,
    ]));
    assert_eq!(response["data"]["dossier"]["namespace"], PRIVATE_NAMESPACE);

    // A widened allow-list still accepts the documented default.
    let default = run(&[
        "list",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--json",
        "--allow-namespace",
        PRIVATE_NAMESPACE,
    ]);
    assert!(default.status.success());
}

#[test]
fn extract_accepts_the_namespace_flag_too() {
    let (output, _directory, output_dir) = extract_with(
        &dossier_in(&text_document(0, "note.txt", "hello"), PRIVATE_NAMESPACE),
        &["--allow-namespace", PRIVATE_NAMESPACE],
    );
    assert!(output.status.success());
    assert_eq!(
        std::fs::read(output_dir.join("note.txt")).unwrap(),
        b"hello"
    );
}

#[test]
fn the_help_documents_the_new_flags() {
    let help = String::from_utf8(run(&["extract", "--help"]).stdout).expect("help is text");
    assert!(help.contains("--allow-namespace <URI>"));
    assert!(help.contains("--no-recursive"));
    assert!(help.contains("--max-depth <N>"));
    let list_help = String::from_utf8(run(&["list", "--help"]).stdout).expect("help is text");
    assert!(list_help.contains("--allow-namespace <URI>"));
}

// ---------------------------------------------------------------------------
// Nested dossiers
// ---------------------------------------------------------------------------

#[test]
fn a_nested_dossier_is_expanded_into_a_subdirectory_by_default() {
    let directory = scratch();
    let output_dir = directory.path().join("out");
    let output = run(&[
        "extract",
        fixture("nested-dossier.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 2);
    assert_eq!(response["data"]["nested_dossiers_extracted"], 1);
    assert_eq!(response["data"]["skipped_count"], 0);

    let extracted = response["data"]["extracted"].as_array().unwrap();
    assert_eq!(extracted[0]["dossier_path"], "0");
    assert_eq!(extracted[0]["path"], "court.dosszie");
    assert_eq!(extracted[0]["filename"], "court.dosszie");
    assert_eq!(extracted[0]["detected_type"], "dossier");
    assert_eq!(extracted[0]["declared_type"], "application/nldossier2");
    assert_eq!(extracted[1]["dossier_path"], "0/0");
    assert_eq!(extracted[1]["path"], "court.dosszie.d/inner.txt");
    assert_eq!(extracted[1]["filename"], "inner.txt");
    assert_eq!(extracted[1]["detected_type"], "text");
    assert_eq!(extracted[1]["declared_type"], "text/plain");

    assert_eq!(
        std::fs::read(output_dir.join("court.dosszie.d").join("inner.txt")).unwrap(),
        b"Nested openSzigno synthetic fixture.\n"
    );
}

#[test]
fn no_recursive_keeps_the_embedded_dossier_as_one_file() {
    let directory = scratch();
    let output_dir = directory.path().join("out");
    let output = run(&[
        "extract",
        fixture("nested-dossier.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
        "--no-recursive",
    ]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 1);
    assert_eq!(response["data"]["nested_dossiers_extracted"], 0);
    assert!(warning_codes(&response).is_empty());
    assert_eq!(count_entries(&output_dir), 1, "no subdirectory is created");
}

/// Two nesting levels, so `--max-depth` has something to stop at.
fn two_level_dossier() -> String {
    let leaf = dossier(&text_document(0, "leaf.txt", "leaf"));
    let middle = dossier(&nested_document(0, "middle.dosszie", leaf.as_bytes()));
    dossier(&nested_document(0, "outer.dosszie", middle.as_bytes()))
}

#[test]
fn max_depth_zero_keeps_every_embedded_dossier_as_a_file() {
    let (output, _directory, output_dir) =
        extract_with(&two_level_dossier(), &["--max-depth", "0"]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 1);
    assert_eq!(response["data"]["nested_dossiers_extracted"], 0);
    assert_eq!(warning_codes(&response), ["nested_dossier_depth_limit"]);
    assert_eq!(count_entries(&output_dir), 1);
    assert!(output_dir.join("outer.dosszie").is_file());
}

#[test]
fn max_depth_one_expands_only_the_first_level() {
    let (output, _directory, output_dir) =
        extract_with(&two_level_dossier(), &["--max-depth", "1"]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 2);
    assert_eq!(response["data"]["nested_dossiers_extracted"], 1);
    let warnings = warning_codes(&response);
    assert_eq!(warnings, ["nested_dossier_depth_limit"]);
    let message = response["warnings"][0]["message"].as_str().unwrap();
    assert!(
        message.contains("0/0"),
        "the warning names the dossier path"
    );

    assert!(
        output_dir
            .join("outer.dosszie.d")
            .join("middle.dosszie")
            .is_file()
    );
    assert!(!output_dir.join("outer.dosszie.d/middle.dosszie.d").exists());
}

#[test]
fn the_default_depth_expands_both_levels() {
    let (output, _directory, output_dir) = extract_with(&two_level_dossier(), &[]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 3);
    assert_eq!(response["data"]["nested_dossiers_extracted"], 2);
    assert!(warning_codes(&response).is_empty());
    let extracted = response["data"]["extracted"].as_array().unwrap();
    assert_eq!(extracted[2]["dossier_path"], "0/0/0");
    assert_eq!(
        extracted[2]["path"],
        "outer.dosszie.d/middle.dosszie.d/leaf.txt"
    );
    assert_eq!(
        std::fs::read(
            output_dir
                .join("outer.dosszie.d")
                .join("middle.dosszie.d")
                .join("leaf.txt")
        )
        .unwrap(),
        b"leaf"
    );
}

#[test]
fn a_depth_above_the_hard_cap_is_clamped_rather_than_refused() {
    let (output, _directory, _output_dir) =
        extract_with(&two_level_dossier(), &["--max-depth", "99"]);
    assert!(output.status.success(), "the value is clamped, not refused");
    assert_eq!(parse_json(&output)["data"]["nested_dossiers_extracted"], 2);
}

#[test]
fn an_unparsable_embedded_dossier_is_reported_and_kept() {
    let xml = dossier(&nested_document(
        0,
        "broken.dosszie",
        b"not a dossier at all",
    ));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success(), "a bad payload never fails the run");
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 1);
    assert_eq!(response["data"]["nested_dossiers_extracted"], 0);
    assert_eq!(warning_codes(&response), ["nested_dossier_invalid"]);
    assert!(
        response["warnings"][0]["message"]
            .as_str()
            .unwrap()
            .contains("invalid_xml"),
        "the core error code is reported"
    );
    assert_eq!(
        std::fs::read(output_dir.join("broken.dosszie")).unwrap(),
        b"not a dossier at all"
    );
}

#[test]
fn an_embedded_dossier_is_found_by_sniffing_even_when_the_type_lies() {
    // Declared `application/octet-stream`, but the payload is a dossier.
    let inner = dossier(&text_document(0, "leaf.txt", "leaf"));
    let xml = dossier(&document(
        0,
        "mislabelled",
        "application",
        "octet-stream",
        None,
        inner.as_bytes(),
    ));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["nested_dossiers_extracted"], 1);
    let extracted = response["data"]["extracted"].as_array().unwrap();
    // The declared type is reported as declared; the sniffed one corrects it.
    assert_eq!(extracted[0]["declared_type"], "application/octet-stream");
    assert_eq!(extracted[0]["detected_type"], "dossier");
    // With no declared extension the sniffed one is appended.
    assert_eq!(extracted[0]["filename"], "mislabelled.es3");
    assert!(
        output_dir
            .join("mislabelled.es3.d")
            .join("leaf.txt")
            .is_file()
    );
}

#[test]
fn structural_warnings_of_an_embedded_dossier_are_reported_too() {
    let inner = dossier(&format!(
        "{}{}",
        "<es:Document><ds:Object/></es:Document>",
        text_document(0, "leaf.txt", "leaf")
    ));
    let xml = dossier(&nested_document(0, "outer.dosszie", inner.as_bytes()));
    let (output, _directory, _output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(warning_codes(&response), ["document_without_profile"]);
    assert!(
        response["warnings"][0]["message"]
            .as_str()
            .unwrap()
            .contains("embedded in document 0"),
        "the warning says which document the finding belongs to"
    );
}

#[test]
fn a_subdirectory_name_that_collides_with_a_file_is_deduplicated() {
    let inner = dossier(&text_document(0, "leaf.txt", "leaf"));
    let xml = dossier(&format!(
        "{}{}",
        nested_document(0, "court.dosszie", inner.as_bytes()),
        // The title already ends in an extension, so nothing is appended and
        // it lands exactly on the subdirectory name.
        document(1, "court.dosszie.d", "text", "plain", None, b"in the way",),
    ));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert!(warning_codes(&response).contains(&"output_name_deduplicated".to_owned()));
    // The embedded dossier keeps `court.dosszie.d`; the later file is renamed.
    assert!(output_dir.join("court.dosszie.d").is_dir());
    assert!(output_dir.join("court.dosszie-1.d").is_file());
    assert_eq!(count_entries(&output_dir), 3);
}

#[test]
fn an_existing_subdirectory_name_stops_the_run_before_anything_is_written() {
    let directory = scratch();
    let input = write_input(directory.path(), &two_level_dossier());
    let output_dir = directory.path().join("out");
    std::fs::create_dir(&output_dir).expect("the output directory is creatable");
    std::fs::write(output_dir.join("outer.dosszie.d"), b"in the way")
        .expect("the blocker is writable");

    let output = run(&[
        "extract",
        input.to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(parse_json(&output)["errors"][0]["code"], "output_exists");
    assert_eq!(
        count_entries(&output_dir),
        1,
        "only the pre-existing entry remains"
    );
}

#[test]
fn a_subdirectory_name_that_is_too_long_is_an_unsafe_output_name() {
    let inner = dossier(&text_document(0, "leaf.txt", "leaf"));
    // 254 bytes of title: a legal filename, but `<name>.d` would be 256.
    let title = "a".repeat(240);
    let xml = dossier(&document(
        0,
        &title,
        "application",
        "nldossier2",
        Some("abcdefghijklmn"),
        inner.as_bytes(),
    ));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert_eq!(output.status.code(), Some(5));
    let response = parse_json(&output);
    assert_eq!(response["errors"][0]["code"], "unsafe_output_name");
    assert!(
        !response["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains(&title),
        "the message must not echo the title"
    );
    assert_eq!(count_entries(&output_dir), 0);
}

// ---------------------------------------------------------------------------
// Sniffing and reporting
// ---------------------------------------------------------------------------

#[test]
fn a_sniffed_extension_is_appended_when_nothing_else_names_one() {
    let xml = dossier(&format!(
        "{}{}{}",
        document(
            0,
            "scan",
            "application",
            "octet-stream",
            None,
            b"%PDF-1.7\n"
        ),
        document(
            1,
            "notice",
            "text",
            "xml",
            None,
            b"<!DOCTYPE html><html><body>x</body></html>",
        ),
        document(2, "blob", "application", "octet-stream", None, &[0u8, 1, 2]),
    ));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success());
    let extracted = parse_json(&output)["data"]["extracted"]
        .as_array()
        .expect("files were extracted")
        .clone();
    assert_eq!(extracted[0]["filename"], "scan.pdf");
    assert_eq!(extracted[0]["detected_type"], "pdf");
    assert_eq!(extracted[0]["declared_type"], "application/octet-stream");
    assert_eq!(extracted[1]["filename"], "notice.html");
    assert_eq!(extracted[1]["detected_type"], "html");
    assert_eq!(extracted[1]["declared_type"], "text/xml");
    // A binary payload has no preferred extension, so the name is unchanged.
    assert_eq!(extracted[2]["filename"], "blob");
    assert_eq!(extracted[2]["detected_type"], "binary");
    assert!(output_dir.join("scan.pdf").is_file());
    assert!(output_dir.join("blob").is_file());
}

#[test]
fn list_and_inspect_report_embedded_dossiers() {
    let path = fixture("nested-dossier.es3");
    let listed = parse_json(&run(&["list", path.to_str().unwrap(), "--json"]));
    assert_eq!(listed["data"]["dossier"]["nested_dossiers"], 1);
    assert_eq!(listed["data"]["documents"][0]["nested_dossier"], true);

    let inspected = parse_json(&run(&["inspect", path.to_str().unwrap(), "--json"]));
    assert_eq!(inspected["data"]["dossier"]["nested_dossiers"], 1);

    let plain = parse_json(&run(&[
        "list",
        fixture("plain-base64.es3").to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(plain["data"]["dossier"]["nested_dossiers"], 0);
    assert_eq!(plain["data"]["documents"][0]["nested_dossier"], false);
}

// ---------------------------------------------------------------------------
// Human output
// ---------------------------------------------------------------------------

#[test]
fn human_list_marks_an_embedded_dossier() {
    let stdout =
        String::from_utf8(run(&["list", fixture("nested-dossier.es3").to_str().unwrap()]).stdout)
            .expect("human output is text");
    assert!(
        stdout.contains(
            "[0] court.dosszie | application/nldossier2 | 903 B | [\"base64\"] | nested dossier\n"
        ),
        "{stdout}"
    );
}

#[test]
fn human_extract_prints_the_relative_path_and_the_detected_type() {
    let directory = scratch();
    let output_dir = directory.path().join("out");
    let output = run(&[
        "extract",
        fixture("nested-dossier.es3").to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("human output is text");
    assert!(stdout.contains("Extracted 2 document(s).\n"), "{stdout}");
    assert!(
        stdout.contains("[0] court.dosszie (903 B, dossier)\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("[0/0] court.dosszie.d/inner.txt (37 B, text)\n"),
        "{stdout}"
    );
}

#[test]
fn human_validate_structure_reports_the_conformance_warning_count() {
    let output = run(&[
        "validate-structure",
        fixture("compatible-namespace.es3").to_str().unwrap(),
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("human output is text");
    assert!(stdout.contains("Conformance warnings: 2"), "{stdout}");
    let stderr = String::from_utf8(output.stderr).expect("diagnostics are text");
    assert!(stderr.contains("warning [dangling_objref]: "), "{stderr}");
    assert!(
        stderr.contains("warning [document_without_profile]: "),
        "{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Output-name deduplication and an absent SourceSize
// ---------------------------------------------------------------------------

#[test]
fn two_documents_with_the_same_title_are_deduplicated() {
    let xml = dossier(&format!(
        "{}{}",
        text_document(0, "x.txt", "first"),
        text_document(1, "x.txt", "second"),
    ));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["extracted_count"], 2);
    assert_eq!(warning_codes(&response), ["output_name_deduplicated"]);
    let message = response["warnings"][0]["message"].as_str().unwrap();
    assert!(
        message.contains('1'),
        "the warning names the document index"
    );
    assert!(!message.contains("x.txt"), "the title is never echoed");

    let extracted = response["data"]["extracted"].as_array().unwrap();
    assert_eq!(extracted[0]["filename"], "x.txt");
    assert_eq!(extracted[0]["path"], "x.txt");
    assert_eq!(extracted[1]["filename"], "x-1.txt");
    assert_eq!(extracted[1]["path"], "x-1.txt");
    assert_eq!(std::fs::read(output_dir.join("x.txt")).unwrap(), b"first");
    assert_eq!(
        std::fs::read(output_dir.join("x-1.txt")).unwrap(),
        b"second"
    );
}

#[test]
fn three_documents_with_the_same_title_each_get_their_own_name() {
    let xml = dossier(&format!(
        "{}{}{}",
        text_document(0, "ruling.txt", "one"),
        text_document(1, "ruling.txt", "two"),
        text_document(2, "ruling.txt", "three"),
    ));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success());
    let response = parse_json(&output);
    let names: Vec<&str> = response["data"]["extracted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["filename"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["ruling.txt", "ruling-1.txt", "ruling-2.txt"]);
    assert_eq!(
        warning_codes(&response),
        ["output_name_deduplicated", "output_name_deduplicated"]
    );
    assert_eq!(count_entries(&output_dir), 3);
}

/// A title crafted to spell the deduplicated name a later document will be
/// given used to abort the whole extraction: deduplication produced one
/// candidate, `stem-<index>`, and a document that had already taken it left
/// nothing to fall back on, so `output_name_collision` was raised and not one
/// file — including every innocent document in the dossier — was written.
/// The candidates now count upwards until one is free.
#[test]
fn a_title_crafted_to_take_the_deduplicated_name_does_not_abort_the_run() {
    let xml = dossier(&format!(
        "{}{}{}{}",
        text_document(0, "ruling.txt", "one"),
        // Exactly the name document 2's deduplication will reach for first.
        text_document(1, "ruling-2.txt", "decoy"),
        text_document(2, "ruling.txt", "two"),
        text_document(3, "keep.txt", "innocent"),
    ));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success(), "the run must not be aborted");
    let response = parse_json(&output);
    let names: Vec<&str> = response["data"]["extracted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["filename"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["ruling.txt", "ruling-2.txt", "ruling-2-2.txt", "keep.txt"]
    );
    assert_eq!(warning_codes(&response), ["output_name_deduplicated"]);
    assert_eq!(count_entries(&output_dir), 4);
    assert_eq!(
        std::fs::read(output_dir.join("ruling-2-2.txt")).unwrap(),
        b"two"
    );
    // The document that never collided is on disk, which is the whole point.
    assert_eq!(
        std::fs::read(output_dir.join("keep.txt")).unwrap(),
        b"innocent"
    );
}

#[test]
fn deduplication_is_scoped_to_one_directory() {
    // The same title inside and outside an embedded dossier is no clash: the
    // nested documents live in their own subdirectory.
    let inner = dossier(&text_document(0, "ruling.txt", "inner"));
    let xml = dossier(&format!(
        "{}{}",
        nested_document(0, "court.dosszie", inner.as_bytes()),
        text_document(1, "ruling.txt", "outer"),
    ));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert!(warning_codes(&response).is_empty());
    assert_eq!(
        std::fs::read(output_dir.join("ruling.txt")).unwrap(),
        b"outer"
    );
    assert_eq!(
        std::fs::read(output_dir.join("court.dosszie.d").join("ruling.txt")).unwrap(),
        b"inner"
    );
}

#[test]
fn duplicate_titles_inside_an_embedded_dossier_are_deduplicated_too() {
    let inner = dossier(&format!(
        "{}{}",
        text_document(0, "leaf.txt", "one"),
        text_document(1, "leaf.txt", "two"),
    ));
    let xml = dossier(&nested_document(0, "court.dosszie", inner.as_bytes()));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(warning_codes(&response), ["output_name_deduplicated"]);
    let extracted = response["data"]["extracted"].as_array().unwrap();
    assert_eq!(extracted[2]["path"], "court.dosszie.d/leaf-1.txt");
    assert_eq!(extracted[2]["dossier_path"], "0/1");
    assert!(
        output_dir
            .join("court.dosszie.d")
            .join("leaf-1.txt")
            .is_file()
    );
}

#[test]
fn two_embedded_dossiers_with_the_same_title_get_separate_subdirectories() {
    let inner = dossier(&text_document(0, "leaf.txt", "leaf"));
    let xml = dossier(&format!(
        "{}{}",
        nested_document(0, "court.dosszie", inner.as_bytes()),
        nested_document(1, "court.dosszie", inner.as_bytes()),
    ));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success());
    let response = parse_json(&output);
    assert_eq!(response["data"]["nested_dossiers_extracted"], 2);
    assert!(
        output_dir
            .join("court.dosszie.d")
            .join("leaf.txt")
            .is_file()
    );
    assert!(
        output_dir
            .join("court-1.dosszie.d")
            .join("leaf.txt")
            .is_file()
    );
    let extracted = response["data"]["extracted"].as_array().unwrap();
    assert_eq!(extracted[2]["path"], "court-1.dosszie");
    assert_eq!(extracted[3]["path"], "court-1.dosszie.d/leaf.txt");
}

/// The pre-write checks run on the deduplicated names, so an existing file
/// that a renamed output would hit still stops the run before anything is
/// written.
#[test]
fn an_existing_file_under_a_deduplicated_name_stops_the_run() {
    let directory = scratch();
    let input = write_input(
        directory.path(),
        &dossier(&format!(
            "{}{}",
            text_document(0, "x.txt", "first"),
            text_document(1, "x.txt", "second"),
        )),
    );
    let output_dir = directory.path().join("out");
    std::fs::create_dir(&output_dir).expect("the output directory is creatable");
    std::fs::write(output_dir.join("x-1.txt"), b"in the way").expect("the blocker is writable");

    let output = run(&[
        "extract",
        input.to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(parse_json(&output)["errors"][0]["code"], "output_exists");
    assert_eq!(
        count_entries(&output_dir),
        1,
        "only the pre-existing entry remains"
    );
}

#[test]
fn a_deduplicated_name_that_would_be_too_long_is_an_unsafe_output_name() {
    // 240 bytes of title plus a 15-byte suffix is exactly 255; the rename
    // would push it past what a filename may be.
    let title = "a".repeat(240);
    let block = |index: usize| {
        document(
            index,
            &title,
            "text",
            "plain",
            Some("abcdefghijklmn"),
            b"payload",
        )
    };
    let xml = dossier(&format!("{}{}", block(0), block(1)));
    let (output, _directory, output_dir) = extract_with(&xml, &[]);
    assert_eq!(output.status.code(), Some(5));
    let response = parse_json(&output);
    assert_eq!(response["errors"][0]["code"], "unsafe_output_name");
    assert!(
        !response["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains(&title),
        "the message must not echo the title"
    );
    assert_eq!(count_entries(&output_dir), 0, "nothing may be written");
}

/// `output_name_collision` survives, for the one case it is still for: every
/// deduplicated candidate taken. Sixty-four candidates are tried, so the
/// dossier below spells all sixty-four of the last document's out in advance —
/// `a-65.txt`, `a-65-2.txt` … `a-65-64.txt` — and then hands it a title that
/// collides. Nothing is written, exactly as before.
#[test]
fn a_name_that_exhausts_every_deduplicated_candidate_is_the_residual_error() {
    let last = 65;
    let mut documents = text_document(0, "a.txt", "one");
    for attempt in 1..=64 {
        let title = match attempt {
            1 => format!("a-{last}.txt"),
            other => format!("a-{last}-{other}.txt"),
        };
        documents.push_str(&text_document(attempt, &title, "decoy"));
    }
    documents.push_str(&text_document(last, "a.txt", "colliding"));

    let (output, _directory, output_dir) = extract_with(&dossier(&documents), &[]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        parse_json(&output)["errors"][0]["code"],
        "output_name_collision"
    );
    assert_eq!(count_entries(&output_dir), 0, "nothing may be written");
}

#[test]
fn a_dossier_without_a_creation_date_is_reported_by_every_command() {
    let directory = scratch();
    let xml = dossier(&text_document(0, "ruling.txt", "hello"));
    let start = xml
        .find("<es:CreationDate>")
        .expect("the dossier profile declares a date");
    let end = xml[start..]
        .find("</es:CreationDate>")
        .expect("the element is closed")
        + start
        + "</es:CreationDate>".len();
    let without_date = format!("{}{}", &xml[..start], &xml[end..]);
    let input = write_input(directory.path(), &without_date);

    for command in ["inspect", "list", "validate-structure"] {
        let output = run(&[command, input.to_str().unwrap(), "--json"]);
        assert!(output.status.success(), "{command} must succeed");
        let response = parse_json(&output);
        assert_eq!(warning_codes(&response), ["creation_date_missing"]);
        if command != "validate-structure" {
            assert!(response["data"]["dossier"]["creation_date"].is_null());
        }
    }
}

#[test]
fn a_document_without_a_source_size_is_reported_by_every_command() {
    let directory = scratch();
    let block = text_document(0, "ruling.txt", "hello");
    let start = block
        .find("<es:SourceSize")
        .expect("the block declares a size");
    let end = block[start..].find("/>").expect("the element is empty") + start + 2;
    let without_size = format!("{}{}", &block[..start], &block[end..]);
    let input = write_input(directory.path(), &dossier(&without_size));

    for command in ["inspect", "list", "validate-structure"] {
        let output = run(&[command, input.to_str().unwrap(), "--json"]);
        assert!(output.status.success(), "{command} must succeed");
        let response = parse_json(&output);
        assert_eq!(warning_codes(&response), ["source_size_missing"]);
        assert!(
            !response["warnings"][0]["message"]
                .as_str()
                .unwrap()
                .contains("ruling"),
            "the warning must not echo the title"
        );
    }

    let listed = parse_json(&run(&["list", input.to_str().unwrap(), "--json"]));
    assert_eq!(listed["data"]["documents"][0]["source_size"], Value::Null);

    let validated = parse_json(&run(&[
        "validate-structure",
        input.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(validated["data"]["conformance_warnings"], 1);
    assert_eq!(validated["data"]["valid_structure"], true);

    // The payload still extracts; nothing is compared against a missing size.
    let output_dir = directory.path().join("out");
    let extracted = run(&[
        "extract",
        input.to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
        "--json",
    ]);
    assert!(extracted.status.success());
    assert_eq!(
        std::fs::read(output_dir.join("ruling.txt")).unwrap(),
        b"hello"
    );

    // Human `list` shows the unknown size rather than inventing one.
    let stdout = String::from_utf8(run(&["list", input.to_str().unwrap()]).stdout)
        .expect("human output is text");
    assert!(stdout.contains("| ? B |"), "{stdout}");
}

// ---------------------------------------------------------------------------
// A PAdES payload
// ---------------------------------------------------------------------------

/// AVDH authenticated a PDF by signing it as a PDF: the result is a PAdES
/// signature inside the payload, which this build does not verify and must not
/// choke on either. `inspect` and `list` describe it as the document it is,
/// `extract` sniffs it as a PDF, and nothing anywhere claims a signature was
/// checked.
#[test]
fn a_pades_pdf_payload_is_reported_as_a_document() {
    // A PDF far too small to be real, carrying the marker a PAdES signature
    // dictionary uses. Nothing here is parsed as PDF by any command.
    let pdf = b"%PDF-1.7\n1 0 obj<</Type/Sig/SubFilter/ETSI.CAdES.detached>>endobj\n%%EOF\n";
    let xml = dossier(&document(
        0,
        "authenticated",
        "application",
        "pdf",
        Some("pdf"),
        pdf,
    ));
    let directory = scratch();
    let input = write_input(directory.path(), &xml);

    for command in ["inspect", "list", "validate-structure"] {
        let output = run(&[command, input.to_str().unwrap(), "--json"]);
        assert!(output.status.success(), "{command} must succeed");
        let response = parse_json(&output);
        assert_eq!(response["ok"], Value::Bool(true));
        assert!(
            warning_codes(&response).is_empty(),
            "{command} must warn about nothing"
        );
    }

    let listed = parse_json(&run(&["list", input.to_str().unwrap(), "--json"]));
    let documents = listed["data"]["documents"]
        .as_array()
        .expect("documents are listed");
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0]["mime_type"]["media_type"], "application");
    assert_eq!(documents[0]["mime_type"]["subtype"], "pdf");
    // The dossier itself carries no XML signature, and the PDF's own is never
    // looked at: nothing was verified, and the output says so.
    assert_eq!(listed["data"]["dossier"]["signatures_present"], 0);
    assert_eq!(
        listed["data"]["dossier"]["signatures_verified"],
        Value::Bool(false)
    );

    let (output, _directory, _output_dir) = extract_with(&xml, &[]);
    assert!(output.status.success());
    let extracted = parse_json(&output)["data"]["extracted"]
        .as_array()
        .expect("files were extracted")
        .clone();
    assert_eq!(extracted[0]["detected_type"], "pdf");
    assert_eq!(extracted[0]["filename"], "authenticated.pdf");
}
