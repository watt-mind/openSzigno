//! `validate-structure`: strict structural checks, and no cryptography.

use std::path::Path;

use openszigno_core::ParseOptions;
use serde_json::json;

use crate::commands::dossier_warnings;
use crate::input::{load, valid_input};
use crate::response::{CliResult, Success};
use crate::sanitize;

pub(crate) fn validate_structure(path: &Path, options: &ParseOptions) -> CliResult {
    let (bytes, dossier) = load(path, options)?;
    let warnings = dossier_warnings(&dossier);
    // This command's own data is counts only, but the pass is applied all the
    // same: it is what keeps a later field from arriving unfiltered.
    let mut data = json!({
        "valid_structure": true,
        "documents": dossier.documents.len(),
        "conformance_warnings": dossier.warnings.len(),
        "cryptographic_verification_performed": false
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
