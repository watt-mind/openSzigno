//! One module per command, plus the dossier summary and the warning lists
//! the reading commands share.

pub(crate) mod create;
pub(crate) mod csc;
pub(crate) mod extract;
pub(crate) mod inspect;
pub(crate) mod list;
pub(crate) mod sign;
pub(crate) mod skill;
pub(crate) mod timestamp;
pub(crate) mod validate;
pub(crate) mod verify;

use openszigno_core::Dossier;
use serde_json::{Value, json};

use crate::response::Notice;

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
        "signature_inventory": {
            "verified": false,
            "signatures": dossier.signatures,
            "timestamps": dossier.timestamps,
        },
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
    dossier_warnings_with(dossier, false)
}

/// The same warnings for a run that may hold a decryption key.
///
/// With a key, `encrypted_document_unsupported` would be untrue: the document
/// is encrypted, and this run can try to decrypt it. What actually happened to
/// it is reported per document by `skip_notice` instead.
fn dossier_warnings_with(dossier: &Dossier, decryption_available: bool) -> Vec<Notice> {
    let mut warnings = capability_warnings(dossier, decryption_available);
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

fn capability_warnings(dossier: &Dossier, decryption_available: bool) -> Vec<Notice> {
    let mut warnings = Vec::new();
    if dossier.signatures_present > 0 || dossier.timestamps_present > 0 {
        warnings.push(Notice {
            code: "cryptographic_verification_not_performed".to_owned(),
            message: "signature and timestamp material was counted but not verified".to_owned(),
        });
    }
    for document in &dossier.documents {
        if document.transforms.iter().any(|item| item == "encrypt") {
            if !decryption_available {
                warnings.push(Notice {
                    code: "encrypted_document_unsupported".to_owned(),
                    message: format!(
                        "document {} is encrypted; only `extract --decrypt-key` can read it",
                        document.index
                    ),
                });
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    use openszigno_core::Limits;

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
        let warnings = capability_warnings(&dossier, false);
        let codes: Vec<&str> = warnings
            .iter()
            .map(|warning| warning.code.as_str())
            .collect();
        assert_eq!(codes, ["encrypted_document_unsupported"]);
    }
}
