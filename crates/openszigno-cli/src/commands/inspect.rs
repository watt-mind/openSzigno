//! `inspect`: identify a dossier and summarize what this tool can do with it.

use std::path::Path;

use openszigno_core::ParseOptions;
use serde_json::json;

use crate::commands::{dossier_overview, dossier_warnings};
use crate::input::{load, valid_input};
use crate::response::{CliResult, Success};
use crate::sanitize;

pub(crate) fn inspect(path: &Path, options: &ParseOptions) -> CliResult {
    let (bytes, dossier) = load(path, options)?;
    let warnings = dossier_warnings(&dossier);
    // Everything a dossier chose is bounded and stripped here, once, so the
    // envelope and the human summary rendered from it are both covered.
    let mut data = json!({
            "dossier": dossier_overview(&dossier),
            "limits": options.limits,
            "capabilities": {
                "structural_validation": true,
                "base64_extraction": true,
                "zip_base64_extraction": true,
                "encrypted_extraction": "with_key",
                "cryptographic_verification": false
            }
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
