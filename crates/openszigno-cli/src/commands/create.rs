//! `create`: build one new, unsigned dossier from files on disk.
//!
//! Everything is decided before anything is written: every input is read and
//! checked, the whole dossier is rendered in memory by `openszigno-author`,
//! and only then is one file created with `O_EXCL`. A run therefore either
//! writes a complete dossier or leaves the destination untouched.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use openszigno_author::{DocumentSpec, DossierSpec};
use openszigno_core::{Limits, ParseOptions};
use openszigno_verify::{Clock, SystemClock, format_rfc3339};
use serde_json::json;

use crate::args::CreateArgs;
use crate::extract::output_dir::OutputDir;
use crate::input::InputInfo;
use crate::response::{CliError, CliResult, Notice, Success, failure};

/// What the envelope reports as the input of a run that reads no dossier.
fn input_info() -> InputInfo {
    InputInfo {
        format: Some("microsec-es3"),
        bytes: None,
    }
}

fn unknown_input() -> InputInfo {
    InputInfo {
        format: None,
        bytes: None,
    }
}

/// Read one file, bounded by `cap` bytes.
///
/// The message never names the path: it is the caller's own path, but the
/// envelope carries no path at all, for every command alike.
fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>, CliError> {
    let metadata =
        fs::metadata(path).map_err(|_| CliError::io("could not inspect an input file"))?;
    if !metadata.is_file() {
        return Err(CliError::io("an input is not a regular file"));
    }
    let too_large = || {
        CliError::invalid(
            "decoded_too_large",
            format!("an input file exceeds {cap} bytes"),
        )
    };
    if metadata.len() > cap {
        return Err(too_large());
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(1024 * 1024) as usize);
    fs::File::open(path)
        .map_err(|_| CliError::io("could not open an input file"))?
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::io("could not read an input file"))?;
    if bytes.len() as u64 > cap {
        return Err(too_large());
    }
    Ok(bytes)
}

/// The basename of `path`, or an empty string when it has none. An empty
/// title is refused by the author crate, with the title rules' own message.
fn basename(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned()
}

/// Parse one `--document PATH[::TITLE[::MIME]]` value.
fn document_spec(value: &str, compress: bool, limits: &Limits) -> Result<DocumentSpec, CliError> {
    let mut parts = value.splitn(3, "::");
    let path = PathBuf::from(parts.next().unwrap_or_default());
    let title = parts
        .next()
        .filter(|title| !title.is_empty())
        .map_or_else(|| basename(&path), str::to_owned);
    let media_type = parts.next().filter(|value| !value.is_empty());
    Ok(DocumentSpec {
        bytes: read_bounded(&path, limits.max_decoded_document_bytes)?,
        title,
        media_type: media_type.map(str::to_owned),
        compress,
    })
}

/// Read one `--embed FILE` and turn it into a nested-dossier document.
///
/// The file is parsed before it is embedded, so `create` never writes a
/// dossier whose embedded document this tool could not read back. The title
/// is the file's stem with the extension the reader's nested-dossier
/// detection recognises.
fn embed_spec(path: &Path, options: &ParseOptions) -> Result<DocumentSpec, CliError> {
    let bytes = read_bounded(path, options.limits.max_input_bytes)?;
    openszigno_core::parse_with_options(&bytes, options).map_err(CliError::structure)?;
    let name = basename(path);
    let stem = name
        .rsplit_once('.')
        .map_or(name.as_str(), |(stem, _)| stem)
        .to_owned();
    Ok(DocumentSpec {
        title: format!("{stem}.{}", openszigno_author::NESTED_DOSSIER_EXTENSION),
        media_type: None,
        bytes,
        compress: false,
    })
}

/// Write `bytes` to `path`, refusing to replace anything that is already
/// there, and removing what this run created if the write fails.
fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            CliError::invalid(
                "invalid_output_path",
                "the output path does not name a file",
            )
        })?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let directory = OutputDir::open(parent).map_err(CliError::from)?;
    let mut file = directory.create_new_file(name).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::unsafe_output(
                "output_exists",
                "an output file already exists or cannot be created safely",
            )
        } else {
            CliError::io("could not create the output file")
        }
    })?;
    if let Err(error) = file
        .write_all(bytes)
        .and_then(|()| file.flush())
        .map_err(|_| CliError::io("could not write the output dossier"))
    {
        // All or nothing: a dossier that was only half written is removed
        // rather than left behind looking like a dossier.
        let removed = directory.remove_file(name).is_ok();
        return Err(if removed {
            error
        } else {
            CliError {
                code: error.code,
                message: format!("{}; the partial output may remain", error.message),
                exit: error.exit,
            }
        });
    }
    Ok(())
}

/// Build the specification the author crate takes, from the command line.
fn build_spec(args: &CreateArgs, options: &ParseOptions) -> Result<DossierSpec, CliError> {
    let mut documents = Vec::with_capacity(args.document.len() + args.embed.len());
    for value in &args.document {
        documents.push(document_spec(value, args.zip, &options.limits)?);
    }
    for path in &args.embed {
        documents.push(embed_spec(path, options)?);
    }
    Ok(DossierSpec {
        title: args.title.clone(),
        created: args.created.as_ref().map_or_else(
            || format_rfc3339(SystemClock.unix_time()),
            |created| created.0.clone(),
        ),
        documents,
    })
}

pub(crate) fn create(args: &CreateArgs) -> CliResult {
    let options = args.parse_options();
    run(args, &options).map_err(|error| failure(unknown_input(), error))
}

fn run(args: &CreateArgs, options: &ParseOptions) -> Result<Success, CliError> {
    let spec = build_spec(args, options)?;
    let dossier = openszigno_author::build(&spec, &options.limits).map_err(CliError::authoring)?;
    write_new_file(&args.output, &dossier.bytes)?;
    Ok(Success {
        input: input_info(),
        data: json!({
            "output": args.output.to_string_lossy(),
            "bytes": dossier.bytes.len(),
            "created": spec.created,
            "documents": dossier.documents,
        }),
        warnings: vec![Notice {
            code: "created_dossier_unsigned".to_owned(),
            message: "the dossier carries no signature and no timestamp".to_owned(),
        }],
        payload: None,
        exit: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_value_splits_into_path_title_and_type() {
        let limits = Limits::default();
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let path = temporary.path().join("hello.txt");
        std::fs::write(&path, b"hello\n").expect("the input is written");
        let value = path.to_str().expect("a UTF-8 path").to_owned();

        let bare = document_spec(&value, false, &limits).expect("a bare path is enough");
        assert_eq!(bare.title, "hello.txt");
        assert_eq!(bare.media_type, None);
        assert_eq!(bare.bytes, b"hello\n");
        assert!(!bare.compress);

        let titled =
            document_spec(&format!("{value}::greeting.txt"), true, &limits).expect("a title");
        assert_eq!(titled.title, "greeting.txt");
        assert!(titled.compress);

        let typed = document_spec(
            &format!("{value}::greeting.bin::application/octet-stream"),
            false,
            &limits,
        )
        .expect("a title and a type");
        assert_eq!(
            typed.media_type.as_deref(),
            Some("application/octet-stream")
        );

        // An empty title or type falls back to the default.
        let empty = document_spec(&format!("{value}::::"), false, &limits).expect("empty parts");
        assert_eq!(empty.title, "hello.txt");
        assert_eq!(empty.media_type, None);
    }

    #[test]
    fn a_missing_input_file_is_an_io_error() {
        let limits = Limits::default();
        let error = document_spec("/nonexistent/openszigno/input.txt", false, &limits)
            .expect_err("the file is not there");
        assert_eq!(error.code, "io_error");
        assert_eq!(error.exit, 3);
    }

    #[test]
    fn an_input_over_the_limit_is_refused() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let path = temporary.path().join("big.txt");
        std::fs::write(&path, vec![b'x'; 32]).expect("the input is written");
        let error = read_bounded(&path, 16).expect_err("over the cap");
        assert_eq!(error.code, "decoded_too_large");
        assert_eq!(error.exit, 4);
    }

    #[test]
    fn an_output_path_that_names_no_file_is_refused() {
        let error = write_new_file(Path::new(".."), b"x").expect_err("no filename");
        assert_eq!(error.code, "invalid_output_path");
        assert_eq!(error.exit, 4);
    }

    #[test]
    fn an_embed_that_is_not_a_dossier_is_a_structural_failure() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let path = temporary.path().join("not-a-dossier.es3");
        std::fs::write(&path, b"<not-a-dossier/>").expect("the input is written");
        let error = embed_spec(&path, &ParseOptions::default()).expect_err("this is not a dossier");
        assert_eq!(error.code, "wrong_root");
        assert_eq!(error.exit, 4);
    }
}
