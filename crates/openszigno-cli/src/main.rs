mod output_dir;
mod revocation_store;
mod trust_store;

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use openszigno_core::{
    DecodeOutcome, DetectedType, Dossier, Error as CoreError, KNOWN_COMPATIBLE_NAMESPACES, Limits,
    ParseOptions, UnsupportedReason,
};
use serde::Serialize;
use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

use openszigno_verify::{
    MemoryRevocationStore, NoRevocation, RoxmltreeC14n, TrustListSnapshot, Verdict, VerifyOptions,
    parse_rfc3339, verify as verify_dossier,
};

use crate::output_dir::{OpenError, OutputDir};

const SCHEMA_VERSION: u32 = 1;

/// Nesting levels `--max-depth` can never exceed, whatever the caller asks
/// for. A flag must not be able to disable a bound.
const MAX_NESTING_DEPTH: u32 = 8;

#[derive(Debug, Parser)]
#[command(
    name = "openszigno",
    version,
    about = "Inspect, extract, and verify Microsec e-Szigno dossiers",
    long_about = "Inspect, extract, and verify Microsec e-Szigno dossiers. `verify` checks XMLDSig/XAdES signatures, certificate paths, and revocation against trust material you supply; it never judges legal authenticity."
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
    /// Verify XMLDSig/XAdES signatures, certificate paths, and revocation.
    Verify(VerifyArgs),
}

/// A validation time from `--at`, kept in both the shape the report needs and
/// the shape the clock needs.
#[derive(Clone, Debug)]
struct ValidationTime {
    text: String,
    unix: i64,
}

/// Parse `--at` during command-line parsing, so an unusable value is a usage
/// error (exit 2) rather than a half-run verification.
fn parse_validation_time(value: &str) -> Result<ValidationTime, String> {
    parse_rfc3339(value)
        .map(|unix| ValidationTime {
            text: value.to_owned(),
            unix,
        })
        .ok_or_else(|| "expected an RFC 3339 timestamp".to_owned())
}

#[derive(Clone, Debug, Args)]
struct VerifyArgs {
    /// Input .es3 dossier.
    file: PathBuf,
    /// Emit one stable JSON object on stdout.
    #[arg(long)]
    json: bool,
    /// Also accept a dossier whose root Dossier element is in this namespace,
    /// in addition to the known-compatible ones. Repeatable.
    #[arg(long = "allow-namespace", value_name = "URI")]
    allow_namespace: Vec<String>,
    /// Directory holding trust anchors (`anchors/`) and optional extra CA
    /// certificates (`intermediates/`), as PEM or DER. Without it every chain
    /// check is `unknown`.
    #[arg(long = "trust-store", value_name = "DIR")]
    trust_store: Option<PathBuf>,
    /// ETSI TS 119 612 trusted list to take trust anchors from, as XML.
    /// Repeatable. Its anchors join the `--trust-store` ones, each reported
    /// with its origin, and only these can make a chain `qualified`.
    #[arg(long = "trust-list", value_name = "FILE")]
    trust_list: Vec<PathBuf>,
    /// Certificate, PEM or DER, that must have signed every `--trust-list`.
    /// Obtain it out of band: for the EU list of trusted lists, from the
    /// Official Journal. Without it the lists are read but reported as
    /// unverified, which caps the verdict at `indeterminate`.
    #[arg(long = "trust-list-signer", value_name = "CERT")]
    trust_list_signer: Option<PathBuf>,
    /// Directory of CRLs (`crls/`) and OCSP responses (`ocsp/`) to check
    /// revocation against, in addition to the signature's own
    /// `xades:RevocationValues`. Nothing is ever fetched.
    #[arg(long = "revocation-store", value_name = "DIR")]
    revocation_store: Option<PathBuf>,
    /// Do not check revocation at all. Documented as producing at most
    /// `indeterminate`: a signature whose certificate might have been revoked
    /// is not one this tool will call valid.
    #[arg(long = "no-revocation")]
    no_revocation: bool,
    /// Validation time as an RFC 3339 timestamp. Overrides everything: without
    /// it, a signature whose timestamp fully verified is validated at that
    /// token's genTime, and otherwise at the current time.
    #[arg(long, value_name = "TIME", value_parser = parse_validation_time)]
    at: Option<ValidationTime>,
    /// Admit SHA-1 digests and RSA-SHA1 signature methods for diagnosis only.
    /// The verdict is capped at `indeterminate` and no failed check can become
    /// a passed one. MD5, HMAC, DSA, and RSA keys below 2048 bits stay refused.
    #[arg(long = "allow-legacy-algorithms")]
    allow_legacy_algorithms: bool,
}

impl VerifyArgs {
    fn parse_options(&self) -> ParseOptions {
        parse_options(&self.allow_namespace)
    }
}

#[derive(Clone, Debug, Args)]
struct InputArgs {
    /// Input .es3 dossier.
    file: PathBuf,
    /// Emit one stable JSON object on stdout.
    #[arg(long)]
    json: bool,
    /// Also accept a dossier whose root Dossier element is in this namespace,
    /// in addition to the known-compatible ones. Repeatable.
    #[arg(long = "allow-namespace", value_name = "URI")]
    allow_namespace: Vec<String>,
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
    /// Also accept a dossier whose root Dossier element is in this namespace,
    /// in addition to the known-compatible ones. Repeatable.
    #[arg(long = "allow-namespace", value_name = "URI")]
    allow_namespace: Vec<String>,
    /// Write embedded dossiers as raw payload files without expanding them.
    #[arg(long)]
    no_recursive: bool,
    /// Nesting levels of embedded dossiers to expand; values above 8 are
    /// clamped to 8.
    #[arg(long, value_name = "N", default_value_t = 3)]
    max_depth: u32,
}

impl InputArgs {
    fn parse_options(&self) -> ParseOptions {
        parse_options(&self.allow_namespace)
    }
}

impl ExtractArgs {
    fn parse_options(&self) -> ParseOptions {
        parse_options(&self.allow_namespace)
    }
}

/// The known-compatible namespaces plus whatever the caller allowed. The
/// allow-list is additive: a flag can widen it but never narrow it away from
/// the documented default.
fn parse_options(allowed: &[String]) -> ParseOptions {
    let mut namespaces: Vec<String> = KNOWN_COMPATIBLE_NAMESPACES
        .iter()
        .map(|namespace| (*namespace).to_owned())
        .collect();
    for namespace in allowed {
        if !namespaces.iter().any(|known| known == namespace) {
            namespaces.push(namespace.clone());
        }
    }
    ParseOptions {
        limits: Limits::default(),
        allowed_namespaces: namespaces,
    }
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
            let result = inspect(&args.file, &args.parse_options());
            ("inspect", args.json, result)
        }
        Command::List(args) => {
            let result = list(&args.file, &args.parse_options());
            ("list", args.json, result)
        }
        Command::Extract(args) => {
            let options = args.parse_options();
            let result = extract(
                &args.file,
                &args.output,
                &options,
                !args.no_recursive,
                args.max_depth.min(MAX_NESTING_DEPTH),
            );
            ("extract", args.json, result)
        }
        Command::ValidateStructure(args) => {
            let result = validate_structure(&args.file, &args.parse_options());
            ("validate-structure", args.json, result)
        }
        Command::Verify(args) => {
            let result = verify_command(&args);
            ("verify", args.json, result)
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
                Ok(()) => ExitCode::from(success.exit),
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
    /// The process exit status for a completed run. `0` for every command
    /// except `verify`, which reports its verdict through statuses 6 and 7.
    exit: u8,
}

struct Failure {
    input: InputInfo,
    error: CliError,
}

type CliResult = Result<Success, Failure>;

fn inspect(path: &Path, options: &ParseOptions) -> CliResult {
    let (bytes, dossier) = load(path, options)?;
    let warnings = dossier_warnings(&dossier);
    Ok(Success {
        input: valid_input(bytes.len()),
        data: json!({
            "dossier": dossier_overview(&dossier),
            "limits": options.limits,
            "capabilities": {
                "structural_validation": true,
                "base64_extraction": true,
                "zip_base64_extraction": true,
                "encrypted_extraction": false,
                "cryptographic_verification": false
            }
        }),
        warnings,
        exit: 0,
    })
}

fn list(path: &Path, options: &ParseOptions) -> CliResult {
    let (bytes, dossier) = load(path, options)?;
    let warnings = dossier_warnings(&dossier);
    Ok(Success {
        input: valid_input(bytes.len()),
        data: json!({
            "dossier": dossier_overview(&dossier),
            "documents": dossier.documents,
        }),
        warnings,
        exit: 0,
    })
}

fn validate_structure(path: &Path, options: &ParseOptions) -> CliResult {
    let (bytes, dossier) = load(path, options)?;
    let warnings = dossier_warnings(&dossier);
    Ok(Success {
        input: valid_input(bytes.len()),
        data: json!({
            "valid_structure": true,
            "documents": dossier.documents.len(),
            "conformance_warnings": dossier.warnings.len(),
            "cryptographic_verification_performed": false
        }),
        warnings,
        exit: 0,
    })
}

/// Verify the XMLDSig signatures of a dossier.
///
/// A structural failure still exits 4, so a caller can tell "this is not a
/// dossier" apart from "this dossier's signatures do not verify". A completed
/// run exits 0 when every signature is `valid`, 6 when any signature is
/// `invalid`, and 7 when the overall verdict is `indeterminate`.
fn verify_command(args: &VerifyArgs) -> CliResult {
    let options = args.parse_options();
    let (bytes, dossier) = load(&args.file, &options)?;
    let input = valid_input(bytes.len());

    let backend = RoxmltreeC14n;
    let store;
    let empty = openszigno_verify::NoTrust;
    let mut snapshots: Vec<TrustListSnapshot> = Vec::new();
    let trust: &dyn openszigno_verify::TrustSource =
        if args.trust_store.is_some() || !args.trust_list.is_empty() {
            let mut loaded = match &args.trust_store {
                Some(directory) => trust_store::load(directory).map_err(|message| {
                    failure(
                        input.clone(),
                        CliError {
                            code: "trust_store_invalid",
                            message,
                            exit: 3,
                        },
                    )
                })?,
                None => openszigno_verify::MemoryTrustStore::default(),
            };
            let signer = match &args.trust_list_signer {
                Some(path) => Some(load_signer(path).map_err(|message| {
                    failure(
                        input.clone(),
                        CliError {
                            code: "trust_list_invalid",
                            message,
                            exit: 3,
                        },
                    )
                })?),
                None => None,
            };
            for path in &args.trust_list {
                let list =
                    load_trust_list(path, signer.as_deref(), &backend).map_err(|message| {
                        failure(
                            input.clone(),
                            CliError {
                                code: "trust_list_invalid",
                                message,
                                exit: 3,
                            },
                        )
                    })?;
                snapshots.push(TrustListSnapshot {
                    territory: list.territory.clone(),
                    sequence_number: list.sequence_number,
                    issue_date: list.issue_date.clone(),
                    next_update: list.next_update.clone(),
                    anchors: list.anchors.len(),
                    signature_verified: list.checks.iter().any(|check| {
                        check.code == openszigno_verify::CheckCode::TrustListSignatureOk
                    }),
                });
                for check in list.checks {
                    loaded.push_check(check);
                }
                loaded.extend_anchors(list.anchors);
            }
            store = loaded;
            &store
        } else {
            &empty
        };

    let system = openszigno_verify::SystemClock;
    let fixed;
    let clock: &dyn openszigno_verify::Clock = match &args.at {
        Some(time) => {
            fixed = openszigno_verify::FixedClock(time.unix);
            &fixed
        }
        None => &system,
    };

    let disabled = NoRevocation;
    let offline;
    let revocation: &dyn openszigno_verify::RevocationSource = if args.no_revocation {
        &disabled
    } else {
        offline = match &args.revocation_store {
            Some(directory) => revocation_store::load(directory).map_err(|message| {
                failure(
                    input.clone(),
                    CliError {
                        code: "revocation_store_invalid",
                        message,
                        exit: 3,
                    },
                )
            })?,
            None => MemoryRevocationStore::default(),
        };
        &offline
    };
    let mut verify_options = VerifyOptions::new(clock, trust, revocation, &backend);
    verify_options.parse = options;
    verify_options.requested_time = args.at.as_ref().map(|time| time.text.clone());
    verify_options.allow_legacy_algorithms = args.allow_legacy_algorithms;

    let mut report = verify_dossier(&bytes, &verify_options)
        .map_err(|error| failure(input.clone(), CliError::structure(error)))?;
    report.policy.trust_lists = snapshots;
    let exit = match report.verdict {
        Verdict::Invalid => 6,
        Verdict::Indeterminate => 7,
        Verdict::Valid => 0,
    };
    let data = serde_json::to_value(&report).map_err(|_| {
        failure(
            input.clone(),
            CliError::io("the result could not be serialised"),
        )
    })?;

    Ok(Success {
        input,
        data,
        // `cryptographic_verification_not_performed` is deliberately absent:
        // verification *was* attempted here, and the verdict says how it went.
        warnings: structural_warnings(&dossier),
        exit,
    })
}

/// Read a `--trust-list-signer` certificate, PEM or DER.
///
/// Exactly one certificate: a file holding several would leave "which one
/// signed the list" ambiguous, and a verifier must not pick.
fn load_signer(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = read_bounded(path, 4 * 1024 * 1024)?;
    let certificates = openszigno_verify::certs::certificates_from_bytes(&bytes)
        .map_err(|reason| format!("the trust-list signer certificate is not usable: {reason}"))?;
    match certificates.len() {
        1 => Ok(certificates.into_iter().next().expect("one certificate")),
        _ => Err("the trust-list signer file must hold exactly one certificate".to_owned()),
    }
}

fn load_trust_list(
    path: &Path,
    signer: Option<&[u8]>,
    backend: &RoxmltreeC14n,
) -> Result<openszigno_verify::TrustList, String> {
    let bytes = read_bounded(
        path,
        openszigno_verify::trustlist::MAX_TRUST_LIST_BYTES as u64,
    )?;
    openszigno_verify::trustlist::load(&bytes, signer, backend)
}

/// Read a regular file, refusing symlinks and anything over `limit` bytes.
/// The message never names the path, because it may be private.
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "a trust material file could not be inspected".to_owned())?;
    if !metadata.is_file() {
        return Err("a trust material path is not a regular file".to_owned());
    }
    if metadata.len() > limit {
        return Err("a trust material file is too large".to_owned());
    }
    fs::read(path).map_err(|_| "a trust material file could not be read".to_owned())
}

/// What one planned output file will become.
struct PlanFile {
    document_index: usize,
    dossier_path: String,
    name: String,
    path: String,
    bytes: Vec<u8>,
    detected_type: &'static str,
    declared_type: String,
}

/// One decoded document being considered for nested expansion.
#[derive(Clone, Copy)]
struct Nested<'a> {
    document: &'a openszigno_core::Document,
    decoded: &'a [u8],
    dossier_path: &'a str,
    name: &'a str,
    directory_path: &'a str,
    depth: u32,
}

/// One planned file, plus the subdirectory holding the dossier it embeds.
struct PlanEntry {
    file: PlanFile,
    subdirectory: Option<PlanDir>,
}

/// One planned output directory: the extraction root, or a `<file>.d`
/// subdirectory holding a nested dossier.
struct PlanDir {
    name: String,
    entries: Vec<PlanEntry>,
}

/// State shared by every nesting level of one extraction run.
struct Plan<'a> {
    options: &'a ParseOptions,
    recursive: bool,
    max_depth: u32,
    /// Decoded bytes across the whole tree, against `max_total_decoded_bytes`.
    total: u64,
    warnings: Vec<Notice>,
    skipped: usize,
    nested_dossiers: usize,
}

fn extract(
    path: &Path,
    output: &Path,
    options: &ParseOptions,
    recursive: bool,
    max_depth: u32,
) -> CliResult {
    let (bytes, dossier) = load(path, options)?;
    let input = valid_input(bytes.len());
    let mut plan = Plan {
        options,
        recursive,
        max_depth,
        total: 0,
        warnings: dossier_warnings(&dossier),
        skipped: 0,
        nested_dossiers: 0,
    };

    // Everything is decoded, named, and checked for collisions across the
    // whole tree before the output directory is touched.
    let root = plan
        .plan_dossier(&dossier, String::new(), "", String::new(), 0)
        .map_err(|error| failure(input.clone(), error))?;

    let directory =
        OutputDir::open(output).map_err(|error| failure(input.clone(), error.into()))?;
    for entry in &root.entries {
        for name in std::iter::once(&entry.file.name)
            .chain(entry.subdirectory.as_ref().map(|sub| &sub.name))
        {
            match directory.exists(name) {
                Ok(false) => {}
                Ok(true) => {
                    return Err(failure(
                        input,
                        CliError::unsafe_output(
                            "output_exists",
                            "an output file already exists; no files were written",
                        ),
                    ));
                }
                Err(_) => {
                    return Err(failure(
                        input,
                        CliError::io("could not safely inspect an output path"),
                    ));
                }
            }
        }
    }

    let mut writer = Writer {
        directories: vec![directory],
        created: Vec::new(),
        extracted: Vec::new(),
    };
    if let Err(error) = writer.write_directory(0, &root) {
        let error = writer.roll_back(error);
        return Err(failure(input, error));
    }

    Ok(Success {
        input,
        data: json!({
            "extracted": writer.extracted,
            "extracted_count": writer.extracted.len(),
            "skipped_count": plan.skipped,
            "nested_dossiers_extracted": plan.nested_dossiers
        }),
        warnings: plan.warnings,
        exit: 0,
    })
}

impl Plan<'_> {
    /// Decode and name every document of one dossier, recursing into the
    /// dossiers it embeds. Nothing is written here.
    ///
    /// `prefix` is the `dossier_path` of the enclosing document with a
    /// trailing slash, `directory_path` the output path of the directory this
    /// dossier extracts into, both relative to the extraction root.
    fn plan_dossier(
        &mut self,
        dossier: &Dossier,
        prefix: String,
        directory_path: &str,
        directory_name: String,
        depth: u32,
    ) -> Result<PlanDir, CliError> {
        let mut entries = Vec::new();
        let mut names = HashSet::new();
        for document in &dossier.documents {
            let dossier_path = format!("{prefix}{}", document.index);
            let decoded = match dossier
                .decode_document(document.index, &self.options.limits)
                .map_err(CliError::extraction)?
            {
                DecodeOutcome::Decoded(decoded) => decoded.bytes,
                DecodeOutcome::Unsupported(reason) => {
                    self.skipped += 1;
                    self.warnings.push(skip_notice(&dossier_path, reason));
                    continue;
                }
            };

            self.total = self
                .total
                .checked_add(decoded.len() as u64)
                .ok_or_else(|| {
                    CliError::unsafe_output("total_size_limit", "aggregate decoded size overflowed")
                })?;
            if self.total > self.options.limits.max_total_decoded_bytes {
                return Err(CliError::unsafe_output(
                    "total_size_limit",
                    "aggregate decoded size exceeds the limit",
                ));
            }

            let detected = openszigno_core::sniff(&decoded);
            let name = safe_output_name(document, fallback_extension(document, detected))?;
            let name = self.claim(&mut names, name, document.index, &dossier_path)?;
            let path = join_path(directory_path, &name);
            let subdirectory = self.plan_nested(
                &Nested {
                    document,
                    decoded: &decoded,
                    dossier_path: &dossier_path,
                    name: &name,
                    directory_path,
                    depth,
                },
                &mut names,
            )?;
            entries.push(PlanEntry {
                file: PlanFile {
                    document_index: document.index,
                    dossier_path,
                    name,
                    path,
                    bytes: decoded,
                    detected_type: detected.as_str(),
                    declared_type: document.mime_type.essence(),
                },
                subdirectory,
            });
        }
        Ok(PlanDir {
            name: directory_name,
            entries,
        })
    }

    /// Take a name in one directory, renaming it deterministically if it is
    /// already taken.
    ///
    /// Real dossiers reuse titles, so a repeated name is deduplicated rather
    /// than failing the run. Only a name that still collides after renaming is
    /// an error.
    fn claim(
        &mut self,
        names: &mut HashSet<String>,
        name: String,
        index: usize,
        dossier_path: &str,
    ) -> Result<String, CliError> {
        if names.insert(name_key(&name)) {
            return Ok(name);
        }
        let renamed = deduplicated_name(&name, index);
        if renamed.len() > 255 {
            return Err(CliError::unsafe_output(
                "unsafe_output_name",
                format!("document {dossier_path} output filename exceeds 255 bytes"),
            ));
        }
        claim_name(names, &renamed)?;
        self.warnings.push(Notice {
            code: "output_name_deduplicated".to_owned(),
            message: format!(
                "document {index} (dossier path {dossier_path}) was renamed because an earlier document already took its output name"
            ),
        });
        Ok(renamed)
    }

    /// Plan the subdirectory for a document that carries an embedded dossier.
    ///
    /// A payload that cannot be parsed is kept as a raw file and reported; it
    /// never fails the run.
    fn plan_nested(
        &mut self,
        request: &Nested<'_>,
        names: &mut HashSet<String>,
    ) -> Result<Option<PlanDir>, CliError> {
        let Nested {
            document,
            decoded,
            dossier_path,
            name,
            directory_path,
            depth,
        } = *request;
        // The declared type and the payload itself both count: real dossiers
        // declare unreliable MIME types.
        let looks_nested =
            document.nested_dossier || openszigno_core::sniff(decoded) == DetectedType::Dossier;
        if !looks_nested || !self.recursive {
            return Ok(None);
        }
        if depth >= self.max_depth {
            self.warnings.push(Notice {
                code: "nested_dossier_depth_limit".to_owned(),
                message: format!(
                    "the dossier embedded in document {dossier_path} was kept as a file because the maximum nesting depth was reached"
                ),
            });
            return Ok(None);
        }
        let nested = match openszigno_core::parse_with_options(decoded, self.options) {
            Ok(nested) => nested,
            Err(error) => {
                self.warnings.push(Notice {
                    code: "nested_dossier_invalid".to_owned(),
                    message: format!(
                        "the dossier embedded in document {dossier_path} could not be parsed ({}) and was kept as a file",
                        error.code().as_str()
                    ),
                });
                return Ok(None);
            }
        };

        let directory_name = format!("{name}.d");
        if directory_name.len() > 255 {
            return Err(CliError::unsafe_output(
                "unsafe_output_name",
                format!("document {dossier_path} output directory name exceeds 255 bytes"),
            ));
        }
        let directory_name = self.claim(names, directory_name, document.index, dossier_path)?;
        for warning in &nested.warnings {
            self.warnings.push(Notice {
                code: warning.code.as_str().to_owned(),
                message: format!(
                    "in the dossier embedded in document {dossier_path}: {}",
                    warning.message
                ),
            });
        }
        self.nested_dossiers += 1;
        let nested_path = join_path(directory_path, &directory_name);
        let plan = self.plan_dossier(
            &nested,
            format!("{dossier_path}/"),
            &nested_path,
            directory_name,
            depth + 1,
        )?;
        Ok(Some(plan))
    }
}

/// The key two names are compared on: NFC-normalised and case-folded, so a
/// case-insensitive filesystem cannot map two outputs onto one file.
fn name_key(name: &str) -> String {
    name.nfc().collect::<String>().to_lowercase()
}

/// Insert `-<index>` before the extension, so a repeated title still yields a
/// distinct, predictable filename.
fn deduplicated_name(name: &str, index: usize) -> String {
    let path = Path::new(name);
    match (
        path.file_stem().and_then(|stem| stem.to_str()),
        path.extension().and_then(|extension| extension.to_str()),
    ) {
        (Some(stem), Some(extension)) if !stem.is_empty() => {
            format!("{stem}-{index}.{extension}")
        }
        _ => format!("{name}-{index}"),
    }
}

/// Reject two documents that would target the same name in one directory.
///
/// Kept for the pathological case that survives deduplication.
fn claim_name(names: &mut HashSet<String>, name: &str) -> Result<(), CliError> {
    if names.insert(name_key(name)) {
        return Ok(());
    }
    Err(CliError::unsafe_output(
        "output_name_collision",
        "two outputs resolve to the same name in one directory",
    ))
}

fn join_path(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else if name.is_empty() {
        directory.to_owned()
    } else {
        format!("{directory}/{name}")
    }
}

/// The extension to append when the title carries none and the dossier
/// declares none either.
fn fallback_extension(
    document: &openszigno_core::Document,
    detected: DetectedType,
) -> Option<&'static str> {
    if document.mime_type.extension.is_some() {
        return None;
    }
    detected.preferred_extension()
}

fn skip_notice(dossier_path: &str, reason: UnsupportedReason) -> Notice {
    match reason {
        UnsupportedReason::Encrypted => Notice {
            code: "document_skipped_encrypted".to_owned(),
            message: format!("document {dossier_path} was not extracted because it is encrypted"),
        },
        UnsupportedReason::TransformChain => Notice {
            code: "document_skipped_unsupported_transform".to_owned(),
            message: format!(
                "document {dossier_path} was not extracted because its transform chain is unsupported"
            ),
        },
    }
}

/// One entry this run created, so that a failure can undo it.
enum Undo {
    File(usize, String),
    Directory(usize, String),
}

/// Writes a planned tree, remembering what it created.
struct Writer {
    directories: Vec<OutputDir>,
    created: Vec<Undo>,
    extracted: Vec<Value>,
}

impl Writer {
    fn write_directory(&mut self, directory: usize, plan: &PlanDir) -> Result<(), CliError> {
        for entry in &plan.entries {
            let mut file = self.directories[directory]
                .create_new_file(&entry.file.name)
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        CliError::unsafe_output(
                            "output_exists",
                            "an output file already exists or cannot be created safely",
                        )
                    } else {
                        CliError::io("could not create an output file")
                    }
                })?;
            self.created
                .push(Undo::File(directory, entry.file.name.clone()));
            file.write_all(&entry.file.bytes)
                .and_then(|()| file.flush())
                .map_err(|_| CliError::io("could not write an extracted document"))?;
            self.extracted.push(json!({
                "document_index": entry.file.document_index,
                "dossier_path": entry.file.dossier_path,
                "filename": entry.file.name,
                "path": entry.file.path,
                "bytes": entry.file.bytes.len(),
                "detected_type": entry.file.detected_type,
                "declared_type": entry.file.declared_type
            }));

            if let Some(nested) = &entry.subdirectory {
                let handle = self.directories[directory]
                    .create_subdirectory(&nested.name)
                    .map_err(CliError::from)?;
                self.created
                    .push(Undo::Directory(directory, nested.name.clone()));
                self.directories.push(handle);
                let child = self.directories.len() - 1;
                self.write_directory(child, nested)?;
            }
        }
        Ok(())
    }

    /// Undo everything this run created, deepest entry first, so a partial
    /// extraction is never left behind.
    fn roll_back(&self, error: CliError) -> CliError {
        let removed = self.created.iter().rev().all(|entry| match entry {
            Undo::File(directory, name) => self.directories[*directory].remove_file(name).is_ok(),
            Undo::Directory(directory, name) => {
                self.directories[*directory].remove_directory(name).is_ok()
            }
        });
        if removed {
            return error;
        }
        CliError {
            code: error.code,
            message: format!("{}; some extracted files may remain", error.message),
            exit: error.exit,
        }
    }
}

fn load(path: &Path, options: &ParseOptions) -> Result<(Vec<u8>, Dossier), Failure> {
    let limits = &options.limits;
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
    let dossier = openszigno_core::parse_with_options(&bytes, options).map_err(|error| {
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
        "nested_dossiers": dossier
            .documents
            .iter()
            .filter(|document| document.nested_dossier)
            .count(),
        "signatures_verified": false
    })
}

/// Every warning a reading command reports for a dossier: what the tool
/// cannot do with it, and how it deviates from the default profile.
fn dossier_warnings(dossier: &Dossier) -> Vec<Notice> {
    let mut warnings = capability_warnings(dossier);
    warnings.extend(structural_warnings(dossier));
    warnings
}

/// The core's structural findings, with their stable codes preserved.
fn structural_warnings(dossier: &Dossier) -> Vec<Notice> {
    dossier
        .warnings
        .iter()
        .map(|warning| Notice {
            code: warning.code.as_str().to_owned(),
            message: warning.message.clone(),
        })
        .collect()
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

/// Derive the output filename from the document title.
///
/// `fallback` is the extension suggested by content sniffing; it is used only
/// when the title carries no extension and the dossier declares none.
fn safe_output_name(
    document: &openszigno_core::Document,
    fallback: Option<&str>,
) -> Result<String, CliError> {
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
    } else if let Some(extension) = fallback
        && Path::new(&name).extension().is_none()
    {
        name.push('.');
        name.push_str(extension);
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
                let nested = if document["nested_dossier"] == Value::Bool(true) {
                    " | nested dossier"
                } else {
                    ""
                };
                writeln!(
                    out,
                    "[{}] {} | {}/{} | {} B | {}{}",
                    document["index"],
                    display_json_string(&document["title"]),
                    display_json_string(&document["mime_type"]["media_type"]),
                    display_json_string(&document["mime_type"]["subtype"]),
                    display_source_size(&document["source_size"]),
                    document["transforms"],
                    nested
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
                    "[{}] {} ({} B, {})",
                    display_json_string(&item["dossier_path"]),
                    display_json_string(&item["path"]),
                    item["bytes"],
                    display_json_string(&item["detected_type"])
                )?;
            }
            writeln!(out, "Extraction is not proof of signature validity.")?;
        }
        "verify" => {
            let data = &response.data;
            writeln!(
                out,
                "Verification verdict: {}",
                display_json_string(&data["verdict"])
            )?;
            writeln!(
                out,
                "Validation time: {}",
                display_json_string(&data["verification_time"]["effective"])
            )?;
            writeln!(out, "Signatures: {}", data["counts"]["signatures"])?;
            if data["policy"]["legacy_algorithms_allowed"] == Value::Bool(true) {
                writeln!(
                    out,
                    "Legacy algorithms were admitted for diagnosis; their strength is not vouched for."
                )?;
            }
            for check in data["checks"].as_array().into_iter().flatten() {
                writeln!(
                    out,
                    "  {}: {}",
                    display_json_string(&check["code"]),
                    display_json_string(&check["status"])
                )?;
            }
            for signature in data["signatures"].as_array().into_iter().flatten() {
                writeln!(
                    out,
                    "[{}] {} signature: {}",
                    signature["index"],
                    display_json_string(&signature["scope"]),
                    display_json_string(&signature["verdict"])
                )?;
                writeln!(
                    out,
                    "  validation time: {} (source: {})",
                    display_json_string(&signature["validation_time"]),
                    display_json_string(&signature["validation_time_source"])
                )?;
                for timestamp in signature["timestamps"].as_array().into_iter().flatten() {
                    writeln!(
                        out,
                        "  {} at {}: {}",
                        display_json_string(&timestamp["kind"]),
                        display_json_string(&timestamp["gen_time"]),
                        if timestamp["verified"] == Value::Bool(true) {
                            "verified"
                        } else {
                            "not verified"
                        }
                    )?;
                    for check in timestamp["checks"].as_array().into_iter().flatten() {
                        writeln!(
                            out,
                            "    {}: {}",
                            display_json_string(&check["code"]),
                            display_json_string(&check["status"])
                        )?;
                    }
                }
                for check in signature["checks"].as_array().into_iter().flatten() {
                    writeln!(
                        out,
                        "  {}: {}",
                        display_json_string(&check["code"]),
                        display_json_string(&check["status"])
                    )?;
                }
            }
            // The boundary, restated on every run.
            writeln!(
                out,
                "Revocation policy: {}. A verdict of `valid` means every check passed at the stated validation time; it is not a legal opinion.",
                display_json_string(&data["policy"]["revocation"])
            )?;
        }
        "validate-structure" => {
            writeln!(
                out,
                "Structure is valid for the supported e-Szigno profile."
            )?;
            writeln!(
                out,
                "Conformance warnings: {} (listed as warnings on stderr).",
                response.data["conformance_warnings"]
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

/// A declared source size, or `?` when the profile omits `SourceSize`.
fn display_source_size(value: &Value) -> String {
    value
        .as_u64()
        .map_or_else(|| "?".to_owned(), |size| size.to_string())
}

fn display_json_string(value: &Value) -> String {
    value.as_str().unwrap_or("<missing>").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory under a fully resolved base path.
    ///
    /// `OutputDir` refuses a path containing a symlink, and the platform
    /// temporary directory is itself a symlink on some systems (macOS resolves
    /// `/var` to `/private/var`), so the base is canonicalized first.
    fn scratch() -> tempfile::TempDir {
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory must resolve");
        tempfile::tempdir_in(base).expect("a temporary directory must be available")
    }

    /// Parse a synthetic, unsigned dossier and return its only document, so
    /// that the private naming rules can be exercised directly.
    fn document(title: &str, extension: Option<&str>) -> openszigno_core::Document {
        let escaped = title
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let extension =
            extension.map_or_else(String::new, |value| format!(" extension=\"{value}\""));
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<es:DossierProfile Id="p0" OBJREF="Object0"><es:Title>Unsigned synthetic fixture</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate></es:DossierProfile>
<es:Documents Id="Object0"><es:Document><es:DocumentProfile Id="p1" OBJREF="o1"><es:Title>{escaped}</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="text" subtype="plain"{extension}/></es:Format><es:SourceSize sizeValue="1" sizeUnit="B"/><es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform></es:DocumentProfile><ds:Object Id="o1">eA==</ds:Object></es:Document></es:Documents>
</es:Dossier>"#
        );
        openszigno_core::parse(xml.as_bytes(), &Limits::default())
            .expect("the synthetic dossier must parse")
            .documents
            .swap_remove(0)
    }

    fn rejected_name(title: &str, extension: Option<&str>) -> CliError {
        safe_output_name(&document(title, extension), None)
            .expect_err("this title must not become a filename")
    }

    fn accepted_name(title: &str, extension: Option<&str>) -> String {
        safe_output_name(&document(title, extension), None).expect("this title must be usable")
    }

    fn sniffed_name(title: &str, fallback: Option<&str>) -> String {
        safe_output_name(&document(title, None), fallback).expect("this title must be usable")
    }

    #[test]
    fn an_ordinary_title_is_used_as_written() {
        assert_eq!(accepted_name("hello.txt", Some("txt")), "hello.txt");
        assert_eq!(
            accepted_name("Report 2026.txt", Some("txt")),
            "Report 2026.txt"
        );
        assert_eq!(accepted_name("no-extension", None), "no-extension");
    }

    #[test]
    fn a_title_is_stored_in_one_canonical_composition() {
        // "e" + U+0301 is written as the single code point U+00E9.
        assert_eq!(
            accepted_name("e\u{301}rte\u{301}s.txt", Some("txt")),
            "\u{e9}rt\u{e9}s.txt"
        );
    }

    #[test]
    fn a_declared_extension_is_appended_only_when_it_is_missing() {
        assert_eq!(accepted_name("invoice", Some("pdf")), "invoice.pdf");
        assert_eq!(accepted_name("invoice.pdf", Some("pdf")), "invoice.pdf");
        assert_eq!(accepted_name("invoice.PDF", Some("pdf")), "invoice.PDF");
        assert_eq!(accepted_name("invoice.txt", Some("pdf")), "invoice.txt.pdf");
    }

    #[test]
    fn a_title_that_hides_reorders_or_escapes_is_rejected() {
        // A title that is empty or only whitespace cannot reach this point: the
        // parser rejects it as a missing element first.
        for title in [
            ".",
            "..",
            ".hidden",
            "-rf",
            "../escape.txt",
            "dir/file.txt",
            "dir\\file.txt",
            "a<b",
            "a>b",
            "a:b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
            // (a C0 control other than tab or newline is not even valid XML)
            "tab\there.txt",
            "line\nbreak.txt",
            "nbsp\u{a0}.txt",
            "soft\u{ad}hyphen.txt",
            "bidi\u{202e}txt.exe",
            "zero\u{200b}width.txt",
            "annotation\u{fff9}.txt",
            "tag\u{e0001}.txt",
            "private\u{e000}.txt",
            "trailing.",
        ] {
            let error = rejected_name(title, None);
            assert_eq!(
                error.code, "unsafe_output_name",
                "{title:?} must be rejected"
            );
            assert_eq!(error.exit, 5);
            assert!(
                !error.message.contains(title),
                "the message must not echo the title"
            );
        }
    }

    #[test]
    fn a_reserved_windows_device_name_is_rejected_on_every_platform() {
        for title in [
            "CON", "con", "PRN", "AUX", "NUL", "nul.txt", "COM1", "com9.log", "LPT1", "lpt9.dat",
        ] {
            assert_eq!(
                rejected_name(title, None).code,
                "unsafe_output_name",
                "{title} is a reserved device name"
            );
        }
        // Only the stem is reserved: a longer name is fine.
        assert_eq!(accepted_name("console.txt", None), "console.txt");
    }

    #[test]
    fn an_over_long_name_is_rejected_before_and_after_the_extension() {
        assert_eq!(
            rejected_name(&"a".repeat(241), None).code,
            "unsafe_output_name"
        );
        assert_eq!(
            rejected_name(&"a".repeat(240), Some("abcdefghijklmnop")).code,
            "unsafe_output_name"
        );
        assert_eq!(accepted_name(&"a".repeat(240), None).len(), 240);
    }

    #[test]
    fn a_declared_extension_that_is_not_a_short_alphanumeric_suffix_is_rejected() {
        for extension in ["tar.gz", "t x", "abcdefghijklmnopq", "-", "txt/", "\u{e9}"] {
            assert_eq!(
                rejected_name("payload", Some(extension)).code,
                "unsafe_output_name",
                "{extension} is not a usable extension"
            );
        }
        assert_eq!(accepted_name("payload", Some("abcdefghijklmnop")).len(), 24);
    }

    #[test]
    fn a_missing_json_string_is_rendered_as_a_placeholder() {
        assert_eq!(display_json_string(&json!("title")), "title");
        assert_eq!(display_json_string(&Value::Null), "<missing>");
        assert_eq!(display_json_string(&json!(7)), "<missing>");
    }

    #[test]
    fn cli_errors_carry_the_documented_exit_status() {
        assert_eq!(CliError::io("x").exit, 3);
        assert_eq!(CliError::invalid("input_too_large", "x").exit, 4);
        assert_eq!(CliError::unsafe_output("output_exists", "x").exit, 5);
        assert_eq!(CliError::io("x").code, "io_error");

        let unsafe_directory = CliError::from(OpenError::Unsafe("not a directory"));
        assert_eq!(unsafe_directory.code, "unsafe_output_directory");
        assert_eq!(unsafe_directory.exit, 5);
        let io = CliError::from(OpenError::Io("cannot inspect"));
        assert_eq!(io.code, "io_error");
        assert_eq!(io.exit, 3);
    }

    #[test]
    fn capability_warnings_name_every_unsupported_document() {
        let dossier = openszigno_core::parse(
            std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/encrypted.es3"),
            )
            .expect("the fixture is readable")
            .as_slice(),
            &Limits::default(),
        )
        .expect("the fixture parses");
        let warnings = capability_warnings(&dossier);
        let codes: Vec<&str> = warnings
            .iter()
            .map(|warning| warning.code.as_str())
            .collect();
        assert_eq!(codes, ["encrypted_document_unsupported"]);
    }

    /// A mid-run failure must not leave a half-extracted directory behind.
    #[test]
    fn roll_back_removes_the_files_and_directories_this_run_created() {
        let temporary = scratch();
        let directory = OutputDir::open(temporary.path()).expect("output directory opens");
        let nested = directory
            .create_subdirectory("nested.d")
            .expect("subdirectory is created");
        for name in ["first.txt", "second.txt"] {
            let mut file = directory.create_new_file(name).expect("file is created");
            file.write_all(b"payload").expect("file is writable");
        }
        let mut inner = nested
            .create_new_file("inner.txt")
            .expect("file is created");
        inner.write_all(b"payload").expect("file is writable");

        let writer = Writer {
            directories: vec![directory, nested],
            created: vec![
                Undo::File(0, "first.txt".to_owned()),
                Undo::File(0, "second.txt".to_owned()),
                Undo::Directory(0, "nested.d".to_owned()),
                Undo::File(1, "inner.txt".to_owned()),
            ],
            extracted: Vec::new(),
        };
        let error = writer.roll_back(CliError::io("could not write an extracted document"));

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
        let temporary = scratch();
        let directory = OutputDir::open(temporary.path()).expect("output directory opens");
        let writer = Writer {
            directories: vec![directory],
            created: vec![Undo::File(0, "never-created.txt".to_owned())],
            extracted: Vec::new(),
        };

        let error = writer.roll_back(CliError::io("could not write an extracted document"));

        assert_eq!(error.code, "io_error");
        assert_eq!(error.exit, 3);
        assert!(error.message.ends_with("; some extracted files may remain"));
    }

    #[test]
    fn a_sniffed_extension_is_appended_only_when_nothing_else_names_one() {
        assert_eq!(sniffed_name("payload", Some("txt")), "payload.txt");
        assert_eq!(sniffed_name("payload.dat", Some("txt")), "payload.dat");
        assert_eq!(sniffed_name("payload", None), "payload");
        // A declared extension always wins over the sniffed one.
        assert_eq!(
            safe_output_name(&document("payload", Some("pdf")), Some("txt"))
                .expect("this title must be usable"),
            "payload.pdf"
        );
    }

    #[test]
    fn a_sniffed_extension_is_used_only_without_a_declared_one() {
        let declared = document("payload", Some("pdf"));
        assert_eq!(fallback_extension(&declared, DetectedType::Text), None);
        let undeclared = document("payload", None);
        assert_eq!(
            fallback_extension(&undeclared, DetectedType::Pdf),
            Some("pdf")
        );
        assert_eq!(fallback_extension(&undeclared, DetectedType::Binary), None);
    }

    #[test]
    fn a_relative_output_path_is_joined_with_forward_slashes() {
        assert_eq!(join_path("", "a.txt"), "a.txt");
        assert_eq!(join_path("a.d", "b.txt"), "a.d/b.txt");
        assert_eq!(join_path("a.d", ""), "a.d");
    }

    #[test]
    fn a_repeated_output_name_in_one_directory_is_a_collision() {
        let mut names = HashSet::new();
        assert!(claim_name(&mut names, "Report.txt").is_ok());
        let error = claim_name(&mut names, "report.TXT").expect_err("names collide");
        assert_eq!(error.code, "output_name_collision");
        assert_eq!(error.exit, 5);
    }

    #[test]
    fn a_skipped_document_names_its_dossier_path_and_reason() {
        assert_eq!(
            skip_notice("2/0", UnsupportedReason::Encrypted).code,
            "document_skipped_encrypted"
        );
        let chain = skip_notice("2/0", UnsupportedReason::TransformChain);
        assert_eq!(chain.code, "document_skipped_unsupported_transform");
        assert!(chain.message.contains("2/0"));
    }
}
