//! `extract`: resolve the selectors, plan the whole tree, and either write it
//! to an output directory or stream one payload to stdout.
//!
//! The decryption material `--decrypt-key` names is loaded here too, before
//! the dossier is touched, so an unusable key fails the run having decoded
//! nothing.

use std::fs;
use std::path::Path;

use openszigno_core::{
    DecodeOutcome, DecryptOptions, DetectedType, Dossier, ParseOptions, RecipientKey,
    decode_document_with,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::args::ExtractArgs;
use crate::commands::dossier_warnings_with;
use crate::extract::ExtractRequest;
use crate::extract::output_dir::OutputDir;
use crate::extract::plan::{Plan, skip_notice};
use crate::extract::select::{Selected, resolve_selection};
use crate::extract::write::Writer;
use crate::input::{InputInfo, load, valid_input};
use crate::response::{CliError, CliResult, Success, failure};

pub(crate) fn extract<'a>(
    path: &Path,
    output: Option<&Path>,
    options: &ParseOptions,
    request: &ExtractRequest<'_>,
    decrypt: DecryptOptions<'a>,
) -> CliResult {
    let (bytes, dossier) = load(path, options)?;
    let input = valid_input(bytes.len());

    let selection = match request.selectors.is_empty() {
        true => None,
        false => Some(
            resolve_selection(&dossier, request.selectors)
                .map_err(|error| failure(input.clone(), error))?,
        ),
    };
    let selected_json = match &selection {
        Some(selected) => Value::Array(
            selected
                .iter()
                .map(|item| json!({ "index": item.index, "object_ref": item.object_ref }))
                .collect(),
        ),
        None => Value::Null,
    };

    if request.to_stdout {
        return extract_to_stdout(
            &dossier,
            selection.as_deref(),
            options,
            request,
            input,
            decrypt,
        );
    }

    let mut plan = Plan {
        options,
        decrypt,
        recursive: request.recursive,
        max_depth: request.max_depth,
        selection: selection
            .as_ref()
            .map(|selected| selected.iter().map(|item| item.index).collect()),
        total: 0,
        warnings: dossier_warnings_with(&dossier, decrypt.key.is_some()),
        skipped: 0,
        nested_dossiers: 0,
    };

    // Everything is decoded, named, and checked for collisions across the
    // whole tree before the output directory is touched.
    let root = plan
        .plan_dossier(&dossier, String::new(), "", String::new(), 0)
        .map_err(|error| failure(input.clone(), error))?;

    let output = output.expect("clap requires --output unless --stdout is given");
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
            "nested_dossiers_extracted": plan.nested_dossiers,
            "selected": selected_json
        }),
        warnings: plan.warnings,
        payload: None,
        exit: 0,
    })
}

/// Decode exactly one document and hand its raw bytes to stdout.
///
/// Nothing is written to the filesystem and nothing but the payload reaches
/// stdout, so a caller can redirect the stream straight into a file. Anything
/// that would make "the payload" ambiguous — no document, several documents,
/// or an embedded dossier that recursion would have turned into a directory —
/// is refused rather than guessed at.
fn extract_to_stdout(
    dossier: &Dossier,
    selection: Option<&[Selected]>,
    options: &ParseOptions,
    request: &ExtractRequest<'_>,
    input: InputInfo,
    decrypt: DecryptOptions<'_>,
) -> CliResult {
    let refuse = |message: &str| {
        failure(
            input.clone(),
            CliError::invalid("stdout_requires_single_document", message.to_owned()),
        )
    };
    let index = match selection {
        Some([only]) => only.index,
        Some(_) => {
            return Err(refuse(
                "--stdout needs exactly one document; the selectors resolved to a different number",
            ));
        }
        None => match dossier.documents.as_slice() {
            [only] => only.index,
            _ => {
                return Err(refuse(
                    "--stdout needs exactly one document; select one with --document",
                ));
            }
        },
    };
    let document = dossier
        .documents
        .iter()
        .find(|item| item.index == index)
        .expect("the selection names a document of this dossier");

    let decoded = match decode_document_with(dossier, index, &options.limits, &decrypt)
        .map_err(|error| failure(input.clone(), CliError::extraction(error)))?
    {
        DecodeOutcome::Decoded(decoded) => decoded,
        DecodeOutcome::Unsupported(reason) => {
            let notice = skip_notice(&index.to_string(), reason);
            return Err(failure(
                input,
                CliError {
                    code: "document_not_extractable",
                    message: notice.message,
                    exit: 5,
                },
            ));
        }
    };

    // An embedded dossier would normally become a payload file *and* a
    // `<file>.d` directory. One byte stream cannot carry both, so the caller
    // must say which they meant by passing --no-recursive.
    if request.recursive
        && (document.nested_dossier
            || openszigno_core::sniff(&decoded.bytes) == DetectedType::Dossier)
    {
        return Err(refuse(
            "the selected document embeds a dossier; pass --no-recursive to write its raw payload, or extract to a directory",
        ));
    }

    let selected_json = json!([{ "index": index, "object_ref": document.object_ref }]);
    let detected = openszigno_core::sniff(&decoded.bytes);
    Ok(Success {
        input,
        data: json!({
            "extracted": [],
            "extracted_count": 0,
            "skipped_count": 0,
            "nested_dossiers_extracted": 0,
            "selected": selected_json,
            "stdout_bytes": decoded.bytes.len(),
            "detected_type": detected.as_str(),
            "decrypted": decoded.decrypted
        }),
        warnings: dossier_warnings_with(dossier, decrypt.key.is_some()),
        payload: Some(decoded.bytes),
        exit: 0,
    })
}

/// The environment variable an encrypted key's passphrase may come from.
///
/// A passphrase must never be a command-line argument: `argv` is readable by
/// every process on most systems and lands in shell history. A file is the
/// documented way; this variable exists for callers that have no place to put
/// one, and `--decrypt-passphrase-file` wins when both are present.
const PASSPHRASE_ENV: &str = "OPENSZIGNO_DECRYPT_PASSPHRASE";

/// The largest decryption-material file this tool reads. A key, a certificate,
/// and a passphrase are all small; the bound keeps a mistyped path from
/// reading something huge into memory.
const MAX_DECRYPT_FILE_BYTES: u64 = 1024 * 1024;

/// Load the recipient key `extract` was given, or `None` when it was given
/// none.
///
/// Nothing read here — key bytes, passphrase, or certificate — is ever placed
/// in a message, a warning, or the JSON envelope. The paths may appear,
/// because the caller typed them and they are how a failure is acted on; the
/// contents never do.
pub(crate) fn load_recipient_key(args: &ExtractArgs) -> Result<Option<RecipientKey>, CliError> {
    let Some(key_path) = args.decrypt_key.as_deref() else {
        return Ok(None);
    };
    let key = read_decrypt_file(key_path, "decryption key")?;
    let certificate = args
        .decrypt_cert
        .as_deref()
        .map(|path| read_decrypt_file(path, "decryption certificate"))
        .transpose()?;
    let passphrase = passphrase(args)?;
    RecipientKey::load(
        &key,
        passphrase.as_deref().map(|bytes| &bytes[..]),
        certificate.as_deref().map(|bytes| &bytes[..]),
    )
    .map(Some)
    .map_err(CliError::decrypt_material)
}

/// The passphrase for an encrypted key: the file if one was named, otherwise
/// the environment variable, otherwise none.
///
/// A file's single trailing newline is stripped, because that is what an
/// editor or `echo` leaves behind and no user means it to be part of the
/// secret. Nothing else is trimmed: a passphrase may legitimately begin or end
/// with a space.
fn passphrase(args: &ExtractArgs) -> Result<Option<Zeroizing<Vec<u8>>>, CliError> {
    if let Some(path) = args.decrypt_passphrase_file.as_deref() {
        let mut bytes = read_decrypt_file(path, "decryption passphrase")?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        return Ok(Some(bytes));
    }
    Ok(std::env::var_os(PASSPHRASE_ENV).map(|value| {
        #[cfg(unix)]
        let bytes = {
            use std::os::unix::ffi::OsStrExt as _;
            value.as_os_str().as_bytes().to_vec()
        };
        #[cfg(not(unix))]
        let bytes = value.to_string_lossy().into_owned().into_bytes();
        Zeroizing::new(bytes)
    }))
}

/// Read one small decryption-material file.
///
/// `what` names the kind of file in the error, never the path's contents. The
/// buffer zeroes itself when it is dropped, so key and passphrase bytes do not
/// linger in freed memory.
fn read_decrypt_file(path: &Path, what: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CliError::io(format!("the {what} file could not be inspected")))?;
    if !metadata.is_file() {
        return Err(CliError::io(format!(
            "the {what} path is not a regular file"
        )));
    }
    if metadata.len() > MAX_DECRYPT_FILE_BYTES {
        return Err(CliError::io(format!("the {what} file is too large")));
    }
    fs::read(path)
        .map(Zeroizing::new)
        .map_err(|_| CliError::io(format!("the {what} file could not be read")))
}
