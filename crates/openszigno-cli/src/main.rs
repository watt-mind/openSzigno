mod output_dir;

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use openszigno_core::{DecodeOutcome, Dossier, Error as CoreError, Limits, UnsupportedReason};
use serde::Serialize;
use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

use crate::output_dir::{OpenError, OutputDir};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "openszigno",
    version,
    about = "Inspect and extract Microsec e-Szigno dossiers",
    long_about = "Inspect and extract Microsec e-Szigno dossiers. This tool does not verify XMLDSig/XAdES signatures or legal authenticity."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Identify a dossier and summarize its capabilities.
    Inspect(InputArgs),
    /// List documents and signature/timestamp presence.
    List(InputArgs),
    /// Extract supported document payloads without overwriting files.
    Extract(ExtractArgs),
    /// Apply strict structural checks (not cryptographic verification).
    ValidateStructure(InputArgs),
}

#[derive(Clone, Debug, Args)]
struct InputArgs {
    /// Input .es3 dossier.
    file: PathBuf,
    /// Emit one stable JSON object on stdout.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Debug, Args)]
struct ExtractArgs {
    /// Input .es3 dossier.
    file: PathBuf,
    /// Destination directory. Existing files are never overwritten.
    #[arg(short, long)]
    output: PathBuf,
    /// Emit one stable JSON object on stdout.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Debug, Serialize)]
struct InputInfo {
    format: Option<&'static str>,
    bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct Notice {
    code: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct Response {
    schema_version: u32,
    ok: bool,
    command: &'static str,
    input: InputInfo,
    data: Value,
    warnings: Vec<Notice>,
    errors: Vec<Notice>,
}

#[derive(Debug)]
struct CliError {
    code: &'static str,
    message: String,
    exit: u8,
}

impl CliError {
    fn io(message: impl Into<String>) -> Self {
        Self {
            code: "io_error",
            message: message.into(),
            exit: 3,
        }
    }

    fn structure(error: CoreError) -> Self {
        Self {
            code: error.code().as_str(),
            message: error.message().to_owned(),
            exit: 4,
        }
    }

    fn extraction(error: CoreError) -> Self {
        Self {
            code: error.code().as_str(),
            message: error.message().to_owned(),
            exit: 5,
        }
    }

    fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            exit: 4,
        }
    }

    fn unsafe_output(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            exit: 5,
        }
    }
}

impl From<OpenError> for CliError {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Unsafe(message) => Self::unsafe_output("unsafe_output_directory", message),
            OpenError::Io(message) => Self::io(message),
        }
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return usage_failure(error),
    };
    let (command, json_mode, result) = match cli.command {
        Command::Inspect(args) => {
            let result = inspect(&args.file);
            ("inspect", args.json, result)
        }
        Command::List(args) => {
            let result = list(&args.file);
            ("list", args.json, result)
        }
        Command::Extract(args) => {
            let result = extract(&args.file, &args.output);
            ("extract", args.json, result)
        }
        Command::ValidateStructure(args) => {
            let result = validate_structure(&args.file);
            ("validate-structure", args.json, result)
        }
    };

    match result {
        Ok(success) => {
            let response = Response {
                schema_version: SCHEMA_VERSION,
                ok: true,
                command,
                input: success.input,
                data: success.data,
                warnings: success.warnings,
                errors: Vec::new(),
            };
            let written = if json_mode {
                write_json(&response)
            } else {
                write_human_success(command, &response)
            };
            match written {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::from(3),
            }
        }
        Err(failure) => {
            let response = Response {
                schema_version: SCHEMA_VERSION,
                ok: false,
                command,
                input: failure.input,
                data: Value::Null,
                warnings: Vec::new(),
                errors: vec![Notice {
                    code: failure.error.code.to_owned(),
                    message: failure.error.message.clone(),
                }],
            };
            let written = if json_mode {
                write_json(&response)
            } else {
                write_diagnostic(&format!(
                    "error [{}]: {}",
                    failure.error.code, failure.error.message
                ));
                Ok(())
            };
            match written {
                Ok(()) => ExitCode::from(failure.error.exit),
                Err(_) => ExitCode::from(3),
            }
        }
    }
}

/// Report a `clap` parse failure.
///
/// In JSON mode the caller still gets exactly one envelope on stdout. The
/// message is deliberately static: `clap`'s own text can quote argument
/// values, which may be private paths.
fn usage_failure(error: clap::Error) -> ExitCode {
    use clap::error::ErrorKind;

    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        error.exit();
    }
    if !std::env::args_os().any(|argument| argument == "--json") {
        error.exit();
    }
    let response = Response {
        schema_version: SCHEMA_VERSION,
        ok: false,
        command: "usage",
        input: InputInfo {
            format: None,
            bytes: None,
        },
        data: Value::Null,
        warnings: Vec::new(),
        errors: vec![Notice {
            code: "usage_error".to_owned(),
            message: "invalid command-line usage".to_owned(),
        }],
    };
    match write_json(&response) {
        Ok(()) => ExitCode::from(2),
        Err(_) => ExitCode::from(3),
    }
}

struct Success {
    input: InputInfo,
    data: Value,
    warnings: Vec<Notice>,
}

struct Failure {
    input: InputInfo,
    error: CliError,
}

type CliResult = Result<Success, Failure>;

fn inspect(path: &Path) -> CliResult {
    let limits = Limits::default();
    let (bytes, dossier) = load(path, &limits)?;
    let warnings = capability_warnings(&dossier);
    Ok(Success {
        input: valid_input(bytes.len()),
        data: json!({
            "dossier": dossier_overview(&dossier),
            "limits": limits,
            "capabilities": {
                "structural_validation": true,
                "base64_extraction": true,
                "zip_base64_extraction": true,
                "encrypted_extraction": false,
                "cryptographic_verification": false
            }
        }),
        warnings,
    })
}

fn list(path: &Path) -> CliResult {
    let limits = Limits::default();
    let (bytes, dossier) = load(path, &limits)?;
    let warnings = capability_warnings(&dossier);
    Ok(Success {
        input: valid_input(bytes.len()),
        data: json!({
            "dossier": dossier_overview(&dossier),
            "documents": dossier.documents,
        }),
        warnings,
    })
}

fn validate_structure(path: &Path) -> CliResult {
    let limits = Limits::default();
    let (bytes, dossier) = load(path, &limits)?;
    let warnings = capability_warnings(&dossier);
    Ok(Success {
        input: valid_input(bytes.len()),
        data: json!({
            "valid_structure": true,
            "documents": dossier.documents.len(),
            "cryptographic_verification_performed": false
        }),
        warnings,
    })
}

fn extract(path: &Path, output: &Path) -> CliResult {
    let limits = Limits::default();
    let (bytes, dossier) = load(path, &limits)?;
    let mut warnings = capability_warnings(&dossier);
    let mut planned = Vec::new();
    let mut names = HashSet::new();
    let mut total = 0u64;

    for document in &dossier.documents {
        match dossier
            .decode_document(document.index, &limits)
            .map_err(|error| failure(valid_input(bytes.len()), CliError::extraction(error)))?
        {
            DecodeOutcome::Decoded(decoded) => {
                total = total
                    .checked_add(decoded.bytes.len() as u64)
                    .ok_or_else(|| {
                        failure(
                            valid_input(bytes.len()),
                            CliError::unsafe_output(
                                "total_size_limit",
                                "aggregate decoded size overflowed",
                            ),
                        )
                    })?;
                if total > limits.max_total_decoded_bytes {
                    return Err(failure(
                        valid_input(bytes.len()),
                        CliError::unsafe_output(
                            "total_size_limit",
                            "aggregate decoded size exceeds the limit",
                        ),
                    ));
                }
                let name = safe_output_name(document)
                    .map_err(|error| failure(valid_input(bytes.len()), error))?;
                // Compare names the way a filesystem might fold them, so that
                // two documents cannot silently target one file.
                if !names.insert(name.nfc().collect::<String>().to_lowercase()) {
                    return Err(failure(
                        valid_input(bytes.len()),
                        CliError::unsafe_output(
                            "output_name_collision",
                            "two documents resolve to the same output filename",
                        ),
                    ));
                }
                planned.push((document.index, name, decoded.bytes));
            }
            DecodeOutcome::Unsupported(UnsupportedReason::Encrypted) => warnings.push(Notice {
                code: "document_skipped_encrypted".to_owned(),
                message: format!(
                    "document {} was not extracted because it is encrypted",
                    document.index
                ),
            }),
            DecodeOutcome::Unsupported(UnsupportedReason::TransformChain) => {
                warnings.push(Notice {
                    code: "document_skipped_unsupported_transform".to_owned(),
                    message: format!(
                        "document {} was not extracted because its transform chain is unsupported",
                        document.index
                    ),
                })
            }
        }
    }

    let directory =
        OutputDir::open(output).map_err(|error| failure(valid_input(bytes.len()), error.into()))?;
    for (_, name, _) in &planned {
        match directory.exists(name) {
            Ok(false) => {}
            Ok(true) => {
                return Err(failure(
                    valid_input(bytes.len()),
                    CliError::unsafe_output(
                        "output_exists",
                        "an output file already exists; no files were written",
                    ),
                ));
            }
            Err(_) => {
                return Err(failure(
                    valid_input(bytes.len()),
                    CliError::io("could not safely inspect an output path"),
                ));
            }
        }
    }

    let mut extracted = Vec::with_capacity(planned.len());
    let mut created: Vec<String> = Vec::with_capacity(planned.len());
    for (index, name, contents) in planned {
        let mut file = match directory.create_new_file(&name) {
            Ok(file) => file,
            Err(error) => {
                let error = if error.kind() == io::ErrorKind::AlreadyExists {
                    CliError::unsafe_output(
                        "output_exists",
                        "an output file already exists or cannot be created safely",
                    )
                } else {
                    CliError::io("could not create an output file")
                };
                return Err(failure(
                    valid_input(bytes.len()),
                    roll_back(&directory, &created, error),
                ));
            }
        };
        created.push(name.clone());
        if file
            .write_all(&contents)
            .and_then(|()| file.flush())
            .is_err()
        {
            return Err(failure(
                valid_input(bytes.len()),
                roll_back(
                    &directory,
                    &created,
                    CliError::io("could not write an extracted document"),
                ),
            ));
        }
        extracted.push(json!({
            "document_index": index,
            "filename": name,
            "bytes": contents.len()
        }));
    }

    Ok(Success {
        input: valid_input(bytes.len()),
        data: json!({
            "extracted": extracted,
            "extracted_count": extracted.len(),
            "skipped_count": dossier.documents.len() - extracted.len()
        }),
        warnings,
    })
}

fn load(path: &Path, limits: &Limits) -> Result<(Vec<u8>, Dossier), Failure> {
    let metadata = fs::metadata(path).map_err(|_| {
        failure(
            InputInfo {
                format: None,
                bytes: None,
            },
            CliError::io("could not inspect the input file"),
        )
    })?;
    if !metadata.is_file() {
        return Err(failure(
            InputInfo {
                format: None,
                bytes: Some(metadata.len()),
            },
            CliError::io("input is not a regular file"),
        ));
    }
    if metadata.len() > limits.max_input_bytes {
        return Err(failure(
            InputInfo {
                format: None,
                bytes: Some(metadata.len()),
            },
            CliError::invalid(
                "input_too_large",
                format!("input exceeds {} bytes", limits.max_input_bytes),
            ),
        ));
    }

    let file = fs::File::open(path).map_err(|_| {
        failure(
            InputInfo {
                format: None,
                bytes: Some(metadata.len()),
            },
            CliError::io("could not open the input file"),
        )
    })?;
    let mut bytes = Vec::with_capacity(metadata.len().min(usize::MAX as u64) as usize);
    file.take(limits.max_input_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| {
            failure(
                InputInfo {
                    format: None,
                    bytes: Some(metadata.len()),
                },
                CliError::io("could not read the input file"),
            )
        })?;
    let dossier = openszigno_core::parse(&bytes, limits).map_err(|error| {
        failure(
            InputInfo {
                format: None,
                bytes: Some(bytes.len() as u64),
            },
            CliError::structure(error),
        )
    })?;
    Ok((bytes, dossier))
}

fn dossier_overview(dossier: &Dossier) -> Value {
    json!({
        "title": dossier.title,
        "category": dossier.category,
        "creation_date": dossier.creation_date,
        "namespace": dossier.namespace,
        "xml_encoding": dossier.xml_encoding,
        "documents": dossier.documents.len(),
        "signatures_present": dossier.signatures_present,
        "timestamps_present": dossier.timestamps_present,
        "signatures_verified": false
    })
}

fn capability_warnings(dossier: &Dossier) -> Vec<Notice> {
    let mut warnings = Vec::new();
    if dossier.signatures_present > 0 || dossier.timestamps_present > 0 {
        warnings.push(Notice {
            code: "cryptographic_verification_not_performed".to_owned(),
            message: "signature and timestamp material was counted but not verified".to_owned(),
        });
    }
    for document in &dossier.documents {
        if document.transforms.iter().any(|item| item == "encrypt") {
            warnings.push(Notice {
                code: "encrypted_document_unsupported".to_owned(),
                message: format!(
                    "document {} is encrypted and cannot be extracted",
                    document.index
                ),
            });
        } else if !matches!(
            document.transforms.as_slice(),
            [base64] if base64 == "base64"
        ) && !matches!(
            document.transforms.as_slice(),
            [zip, base64] if zip == "zip" && base64 == "base64"
        ) {
            warnings.push(Notice {
                code: "unsupported_transform_chain".to_owned(),
                message: format!(
                    "document {} uses an unsupported transform chain",
                    document.index
                ),
            });
        }
    }
    warnings
}

/// Characters that carry no visible glyph but can reorder, hide, or spoof the
/// rest of a filename: soft hyphen, bidi controls and isolates, zero-width
/// characters, line/paragraph separators, byte order mark, interlinear
/// annotation, tag characters, and the noncharacters at the end of the BMP.
fn is_invisible_or_formatting(character: char) -> bool {
    matches!(
        character,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{FFFE}'
            | '\u{FFFF}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// Private Use Area code points render differently on every system, so they
/// cannot be shown to a user as a trustworthy filename.
fn is_private_use(character: char) -> bool {
    matches!(
        character,
        '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}'
    )
}

fn safe_output_name(document: &openszigno_core::Document) -> Result<String, CliError> {
    let title = document.title.trim();
    if title.is_empty()
        || title == "."
        || title == ".."
        || title.starts_with(['.', '-'])
        || title.chars().any(|character| {
            character.is_control()
                || (character.is_whitespace() && character != ' ')
                || is_invisible_or_formatting(character)
                || is_private_use(character)
                || matches!(
                    character,
                    '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*'
                )
        })
        || title.ends_with(['.', ' '])
        || title.len() > 240
    {
        return Err(CliError::unsafe_output(
            "unsafe_output_name",
            format!("document {} has an unsafe output title", document.index),
        ));
    }
    let path = Path::new(title);
    if path.is_absolute()
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(CliError::unsafe_output(
            "unsafe_output_name",
            format!("document {} has an unsafe output path", document.index),
        ));
    }
    let stem = title
        .split('.')
        .next()
        .unwrap_or(title)
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        return Err(CliError::unsafe_output(
            "unsafe_output_name",
            format!("document {} uses a reserved output title", document.index),
        ));
    }

    // Write one canonical spelling, so that two differently composed titles
    // cannot resolve to the same file behind our back.
    let mut name = title.nfc().collect::<String>();
    if let Some(extension) = document.mime_type.extension.as_deref() {
        if extension.is_empty()
            || extension.len() > 16
            || !extension
                .chars()
                .all(|character| character.is_ascii_alphanumeric())
        {
            return Err(CliError::unsafe_output(
                "unsafe_output_name",
                format!("document {} has an unsafe file extension", document.index),
            ));
        }
        let suffix = format!(".{extension}");
        if !name
            .to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase())
        {
            name.push_str(&suffix);
        }
    }
    if name.len() > 255 {
        return Err(CliError::unsafe_output(
            "unsafe_output_name",
            format!(
                "document {} output filename exceeds 255 bytes",
                document.index
            ),
        ));
    }
    Ok(name)
}

/// Undo the files this run created, so a partial extraction is never left
/// behind. The original error is returned, or a variant of it when the
/// cleanup itself could not complete.
fn roll_back(directory: &OutputDir, created: &[String], error: CliError) -> CliError {
    let removed = created
        .iter()
        .all(|name| directory.remove_file(name).is_ok());
    if removed {
        return error;
    }
    CliError {
        code: error.code,
        message: format!("{}; some extracted files may remain", error.message),
        exit: error.exit,
    }
}

fn valid_input(bytes: usize) -> InputInfo {
    InputInfo {
        format: Some("microsec-es3"),
        bytes: Some(bytes as u64),
    }
}

fn failure(input: InputInfo, error: CliError) -> Failure {
    Failure { input, error }
}

/// Write the single JSON envelope. A closed or failing stdout is an I/O
/// failure the caller turns into exit status 3, never a panic.
fn write_json(response: &Response) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(response).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(&bytes)?;
    stdout.flush()
}

/// Best-effort diagnostic on stderr; a failing stderr must not abort the run.
fn write_diagnostic(line: &str) {
    let _ = writeln!(io::stderr(), "{line}");
}

fn write_human_success(command: &str, response: &Response) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match command {
        "inspect" => {
            let dossier = &response.data["dossier"];
            writeln!(out, "Microsec e-Szigno dossier")?;
            writeln!(out, "Title: {}", display_json_string(&dossier["title"]))?;
            writeln!(out, "Documents: {}", dossier["documents"])?;
            writeln!(
                out,
                "Signatures present: {} (not verified)",
                dossier["signatures_present"]
            )?;
            writeln!(
                out,
                "Timestamps present: {} (not verified)",
                dossier["timestamps_present"]
            )?;
        }
        "list" => {
            let dossier = &response.data["dossier"];
            writeln!(out, "{}", display_json_string(&dossier["title"]))?;
            for document in response.data["documents"].as_array().into_iter().flatten() {
                writeln!(
                    out,
                    "[{}] {} | {}/{} | {} B | {}",
                    document["index"],
                    display_json_string(&document["title"]),
                    display_json_string(&document["mime_type"]["media_type"]),
                    display_json_string(&document["mime_type"]["subtype"]),
                    document["source_size"],
                    document["transforms"]
                )?;
            }
            writeln!(
                out,
                "Signatures/timestamps are listed by presence only; none were verified."
            )?;
        }
        "extract" => {
            writeln!(
                out,
                "Extracted {} document(s).",
                response.data["extracted_count"]
            )?;
            for item in response.data["extracted"].as_array().into_iter().flatten() {
                writeln!(
                    out,
                    "[{}] {} ({} B)",
                    item["document_index"],
                    display_json_string(&item["filename"]),
                    item["bytes"]
                )?;
            }
            writeln!(out, "Extraction is not proof of signature validity.")?;
        }
        "validate-structure" => {
            writeln!(
                out,
                "Structure is valid for the supported e-Szigno profile."
            )?;
            writeln!(out, "Cryptographic verification was not performed.")?;
        }
        _ => {}
    }
    out.flush()?;
    for warning in &response.warnings {
        write_diagnostic(&format!("warning [{}]: {}", warning.code, warning.message));
    }
    Ok(())
}

fn display_json_string(value: &Value) -> String {
    value.as_str().unwrap_or("<missing>").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mid-run failure must not leave a half-extracted directory behind.
    #[test]
    fn roll_back_removes_the_files_this_run_created() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let directory = OutputDir::open(temporary.path()).expect("output directory opens");
        for name in ["first.txt", "second.txt"] {
            let mut file = directory.create_new_file(name).expect("file is created");
            file.write_all(b"payload").expect("file is writable");
        }

        let created = vec!["first.txt".to_owned(), "second.txt".to_owned()];
        let error = roll_back(
            &directory,
            &created,
            CliError::io("could not write an extracted document"),
        );

        assert_eq!(error.code, "io_error");
        assert_eq!(error.message, "could not write an extracted document");
        assert_eq!(
            std::fs::read_dir(temporary.path())
                .expect("output directory is readable")
                .count(),
            0
        );
    }

    /// A failed cleanup keeps the code but says so, so a caller never assumes
    /// the destination is clean.
    #[test]
    fn roll_back_reports_that_files_may_remain() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let directory = OutputDir::open(temporary.path()).expect("output directory opens");
        let created = vec!["never-created.txt".to_owned()];

        let error = roll_back(
            &directory,
            &created,
            CliError::io("could not write an extracted document"),
        );

        assert_eq!(error.code, "io_error");
        assert_eq!(error.exit, 3);
        assert!(error.message.ends_with("; some extracted files may remain"));
    }
}
