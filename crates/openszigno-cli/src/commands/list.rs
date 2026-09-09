//! `list`: the documents of a dossier, and its signature/timestamp presence.

use std::path::Path;

use openszigno_core::ParseOptions;
use serde_json::json;

use crate::commands::{dossier_overview, dossier_warnings};
use crate::input::{load, valid_input};
use crate::response::{CliResult, Success};
use crate::sanitize;

pub(crate) fn list(path: &Path, options: &ParseOptions) -> CliResult {
    let (bytes, dossier) = load(path, options)?;
    let warnings = dossier_warnings(&dossier);
    // Document titles and MIME type halves are the strings a hostile dossier
    // most wants on a terminal; they are bounded and stripped here, once.
    let mut data = json!({
        "dossier": dossier_overview(&dossier),
        "documents": dossier.documents,
    });
    sanitize::data(&mut data);
    Ok(Success {
        input: valid_input(bytes.len()),
        data,
        warnings,
        payload: None,
        exit: 0,
    })
}
