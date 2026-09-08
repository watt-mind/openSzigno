//! The one bounded reader every command takes its input through, and the
//! `InputInfo` block the JSON envelope reports about it.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use openszigno_core::{Dossier, Limits, ParseOptions};
use serde::Serialize;

use crate::response::{CliError, Failure, failure};

#[derive(Clone, Debug, Serialize)]
pub(crate) struct InputInfo {
    pub(crate) format: Option<&'static str>,
    pub(crate) bytes: Option<u64>,
}

/// The one bounded reader every command takes its input through.
///
/// `path` is either a regular file or `-`, which means standard input. Both
/// paths read at most `max_input_bytes + 1` bytes and reject the input when
/// that many arrive, so the cap holds without trusting filesystem metadata —
/// which a pipe has none of, and which a file can change under us anyway. The
/// whole dossier is buffered in memory either way; that is inherent to the
/// format, whose XML must be parsed as one tree.
fn read_input(path: &Path, limits: &Limits) -> Result<Vec<u8>, Failure> {
    let unknown = || InputInfo {
        format: None,
        bytes: None,
    };
    let cap = limits.max_input_bytes.saturating_add(1);
    let (mut source, declared): (Box<dyn Read>, Option<u64>) = if path == Path::new("-") {
        (Box::new(io::stdin().lock()), None)
    } else {
        let metadata = fs::metadata(path)
            .map_err(|_| failure(unknown(), CliError::io("could not inspect the input file")))?;
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
                too_large(limits),
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
        (Box::new(file), Some(metadata.len()))
    };

    let mut bytes = Vec::with_capacity(declared.unwrap_or(0).min(1024 * 1024) as usize);
    source
        .by_ref()
        .take(cap)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            failure(
                InputInfo {
                    format: None,
                    bytes: declared,
                },
                CliError::io("could not read the input"),
            )
        })?;
    if bytes.len() as u64 > limits.max_input_bytes {
        // The true size is unknown: reading stopped one byte past the cap. The
        // envelope says so rather than reporting the truncated length as if it
        // were the input size.
        return Err(failure(unknown(), too_large(limits)));
    }
    Ok(bytes)
}

fn too_large(limits: &Limits) -> CliError {
    CliError::invalid(
        "input_too_large",
        format!("input exceeds {} bytes", limits.max_input_bytes),
    )
}

pub(crate) fn load(path: &Path, options: &ParseOptions) -> Result<(Vec<u8>, Dossier), Failure> {
    let bytes = read_input(path, &options.limits)?;
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

pub(crate) fn valid_input(bytes: usize) -> InputInfo {
    InputInfo {
        format: Some("microsec-es3"),
        bytes: Some(bytes as u64),
    }
}
