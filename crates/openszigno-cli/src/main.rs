use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use openszigno_core::{DecodeOutcome, Dossier, Error as CoreError, Limits, UnsupportedReason};
use serde::Serialize;
use serde_json::{Value, json};

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

fn main() -> ExitCode {
    let cli = Cli::parse();
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
            if json_mode {
                write_json(&response);
            } else {
                write_human_success(command, &response);
            }
            ExitCode::SUCCESS
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
            if json_mode {
                write_json(&response);
            } else {
                eprintln!("error [{}]: {}", failure.error.code, failure.error.message);
            }
            ExitCode::from(failure.error.exit)
        }
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
                if !names.insert(name.to_lowercase()) {
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

    prepare_output_directory(output).map_err(|error| failure(valid_input(bytes.len()), error))?;
    for (_, name, _) in &planned {
        match fs::symlink_metadata(output.join(name)) {
            Ok(_) => {
                return Err(failure(
                    valid_input(bytes.len()),
                    CliError::unsafe_output(
                        "output_exists",
                        "an output file already exists; no files were written",
                    ),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(failure(
                    valid_input(bytes.len()),
                    CliError::io("could not safely inspect an output path"),
                ));
            }
        }
    }
    let mut extracted = Vec::with_capacity(planned.len());
    for (index, name, contents) in planned {
        let destination = output.join(&name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|_| {
                failure(
                    valid_input(bytes.len()),
                    CliError::unsafe_output(
                        "output_exists",
                        "an output file already exists or cannot be created safely",
                    ),
                )
            })?;
        file.write_all(&contents).map_err(|_| {
            failure(
                valid_input(bytes.len()),
                CliError::io("could not write an extracted document"),
            )
        })?;
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

fn safe_output_name(document: &openszigno_core::Document) -> Result<String, CliError> {
    let title = document.title.trim();
    if title.is_empty()
        || title == "."
        || title == ".."
        || title.chars().any(|character| {
            character.is_control()
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

    let mut name = title.to_owned();
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

fn prepare_output_directory(output: &Path) -> Result<(), CliError> {
    reject_symlink_components(output)?;
    fs::create_dir_all(output)
        .map_err(|_| CliError::io("could not create the output directory"))?;
    reject_symlink_components(output)?;
    let metadata = fs::symlink_metadata(output)
        .map_err(|_| CliError::io("could not inspect the output directory"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(CliError::unsafe_output(
            "unsafe_output_directory",
            "output must be a real directory, not a symlink",
        ));
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), CliError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(CliError::unsafe_output(
                    "unsafe_output_directory",
                    "output directory path must not contain symlinks",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(CliError::io(
                    "could not safely inspect the output directory path",
                ));
            }
        }
    }
    Ok(())
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

fn write_json(response: &Response) {
    serde_json::to_writer(std::io::stdout().lock(), response)
        .expect("serializing the JSON response cannot fail");
    println!();
}

fn write_human_success(command: &str, response: &Response) {
    match command {
        "inspect" => {
            let dossier = &response.data["dossier"];
            println!("Microsec e-Szigno dossier");
            println!("Title: {}", display_json_string(&dossier["title"]));
            println!("Documents: {}", dossier["documents"]);
            println!(
                "Signatures present: {} (not verified)",
                dossier["signatures_present"]
            );
            println!(
                "Timestamps present: {} (not verified)",
                dossier["timestamps_present"]
            );
        }
        "list" => {
            let dossier = &response.data["dossier"];
            println!("{}", display_json_string(&dossier["title"]));
            for document in response.data["documents"].as_array().into_iter().flatten() {
                println!(
                    "[{}] {} | {}/{} | {} B | {}",
                    document["index"],
                    display_json_string(&document["title"]),
                    display_json_string(&document["mime_type"]["media_type"]),
                    display_json_string(&document["mime_type"]["subtype"]),
                    document["source_size"],
                    document["transforms"]
                );
            }
            println!("Signatures/timestamps are listed by presence only; none were verified.");
        }
        "extract" => {
            println!(
                "Extracted {} document(s).",
                response.data["extracted_count"]
            );
            for item in response.data["extracted"].as_array().into_iter().flatten() {
                println!(
                    "[{}] {} ({} B)",
                    item["document_index"],
                    display_json_string(&item["filename"]),
                    item["bytes"]
                );
            }
        }
        "validate-structure" => {
            println!("Structure is valid for the supported e-Szigno profile.");
            println!("Cryptographic verification was not performed.");
        }
        _ => unreachable!("known command"),
    }
    for warning in &response.warnings {
        eprintln!("warning [{}]: {}", warning.code, warning.message);
    }
}

fn display_json_string(value: &Value) -> String {
    value.as_str().unwrap_or("<missing>").to_owned()
}
