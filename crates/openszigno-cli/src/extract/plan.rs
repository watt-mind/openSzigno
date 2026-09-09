//! Planning an extraction: decode every document, name it, deduplicate the
//! names, and recurse into the dossiers documents embed. Nothing is written.

use std::collections::HashSet;

use openszigno_core::{
    DecodeOutcome, DecryptOptions, DetectedType, Dossier, ParseOptions, UnsupportedReason,
    decode_document_with,
};

use crate::extract::names::{
    MAX_DEDUPLICATION_ATTEMPTS, deduplicated_name, fallback_extension, join_path, name_collision,
    safe_output_name, try_claim_name,
};
use crate::response::{CliError, Notice};

/// What one planned output file will become.
pub(crate) struct PlanFile {
    pub(crate) document_index: usize,
    pub(crate) dossier_path: String,
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) bytes: Vec<u8>,
    /// Whether an `encrypt` transform was reversed to obtain `bytes`. It says
    /// a key unwrapped the content, never that anything was verified.
    pub(crate) decrypted: bool,
    pub(crate) detected_type: &'static str,
    pub(crate) declared_type: String,
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
pub(crate) struct PlanEntry {
    pub(crate) file: PlanFile,
    pub(crate) subdirectory: Option<PlanDir>,
}

/// One planned output directory: the extraction root, or a `<file>.d`
/// subdirectory holding a nested dossier.
pub(crate) struct PlanDir {
    pub(crate) name: String,
    pub(crate) entries: Vec<PlanEntry>,
}

/// State shared by every nesting level of one extraction run.
pub(crate) struct Plan<'a> {
    pub(crate) options: &'a ParseOptions,
    /// The decryption policy for this run. `DecryptOptions::default()` leaves
    /// every encrypted document skipped, which is what `extract` does without
    /// `--decrypt-key`.
    pub(crate) decrypt: DecryptOptions<'a>,
    pub(crate) recursive: bool,
    pub(crate) max_depth: u32,
    /// Top-level document indices to extract, or `None` for all of them.
    /// It applies at depth 0 only: `--document` never reaches into an
    /// embedded dossier, so a selected nested dossier still expands whole.
    pub(crate) selection: Option<Vec<usize>>,
    /// Decoded bytes across the whole tree, against `max_total_decoded_bytes`.
    pub(crate) total: u64,
    pub(crate) warnings: Vec<Notice>,
    pub(crate) skipped: usize,
    pub(crate) nested_dossiers: usize,
}

impl Plan<'_> {
    /// Decode and name every document of one dossier, recursing into the
    /// dossiers it embeds. Nothing is written here.
    ///
    /// `prefix` is the `dossier_path` of the enclosing document with a
    /// trailing slash, `directory_path` the output path of the directory this
    /// dossier extracts into, both relative to the extraction root.
    pub(crate) fn plan_dossier(
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
            // The selection applies to the top level only. A document left out
            // by it was never asked for, so it is not a skip: `skipped_count`
            // stays a count of documents this tool could not decode.
            if depth == 0
                && let Some(selected) = &self.selection
                && !selected.contains(&document.index)
            {
                continue;
            }
            let dossier_path = format!("{prefix}{}", document.index);
            let decoded = match decode_document_with(
                dossier,
                document.index,
                &self.options.limits,
                &self.decrypt,
            )
            .map_err(CliError::extraction)?
            {
                DecodeOutcome::Decoded(decoded) => decoded,
                DecodeOutcome::Unsupported(reason) => {
                    self.skipped += 1;
                    self.warnings.push(skip_notice(&dossier_path, reason));
                    continue;
                }
            };

            self.total = self
                .total
                .checked_add(decoded.bytes.len() as u64)
                .ok_or_else(|| {
                    CliError::unsafe_output("total_size_limit", "aggregate decoded size overflowed")
                })?;
            if self.total > self.options.limits.max_total_decoded_bytes {
                return Err(CliError::unsafe_output(
                    "total_size_limit",
                    "aggregate decoded size exceeds the limit",
                ));
            }

            let detected = openszigno_core::sniff(&decoded.bytes);
            let name = safe_output_name(document, fallback_extension(document, detected))?;
            let name = self.claim(&mut names, name, document.index, &dossier_path)?;
            let path = join_path(directory_path, &name);
            let subdirectory = self.plan_nested(
                &Nested {
                    document,
                    decoded: &decoded.bytes,
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
                    decrypted: decoded.decrypted,
                    bytes: decoded.bytes,
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
    /// than failing the run. The renaming keeps counting — `stem-<index>`,
    /// then `stem-<index>-2`, `-3` and on — because a title crafted to spell
    /// the deduplicated name a *later* document will be given would otherwise
    /// collide once and abort the whole extraction, writing nothing at all.
    /// Only a name still taken after [`MAX_DEDUPLICATION_ATTEMPTS`] candidates
    /// is `output_name_collision`.
    fn claim(
        &mut self,
        names: &mut HashSet<String>,
        name: String,
        index: usize,
        dossier_path: &str,
    ) -> Result<String, CliError> {
        if try_claim_name(names, &name) {
            return Ok(name);
        }
        let mut renamed = None;
        for attempt in 1..=MAX_DEDUPLICATION_ATTEMPTS {
            let candidate = deduplicated_name(&name, index, attempt);
            if candidate.len() > 255 {
                return Err(CliError::unsafe_output(
                    "unsafe_output_name",
                    format!("document {dossier_path} output filename exceeds 255 bytes"),
                ));
            }
            if try_claim_name(names, &candidate) {
                renamed = Some(candidate);
                break;
            }
        }
        let renamed = renamed.ok_or_else(name_collision)?;
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

pub(crate) fn skip_notice(dossier_path: &str, reason: UnsupportedReason) -> Notice {
    match reason {
        UnsupportedReason::Encrypted => Notice {
            code: "document_skipped_encrypted".to_owned(),
            message: format!(
                "document {dossier_path} was not extracted because it is encrypted and no --decrypt-key was given"
            ),
        },
        UnsupportedReason::TransformChain => Notice {
            code: "document_skipped_unsupported_transform".to_owned(),
            message: format!(
                "document {dossier_path} was not extracted because its transform chain is unsupported"
            ),
        },
        UnsupportedReason::NoMatchingRecipient => Notice {
            code: "document_skipped_no_matching_recipient".to_owned(),
            message: format!(
                "document {dossier_path} was not extracted because none of its CMS recipients names the certificate given for the decryption key"
            ),
        },
        // The OID is the sender's algorithm choice, not payload content, so
        // naming it is safe and is the only way a caller can act on this.
        UnsupportedReason::UnsupportedCipher { oid } => Notice {
            code: "document_skipped_unsupported_cipher".to_owned(),
            message: format!(
                "document {dossier_path} was not extracted because it uses the unsupported algorithm {oid}"
            ),
        },
        UnsupportedReason::LegacyCipher { oid } => Notice {
            code: "document_skipped_legacy_cipher".to_owned(),
            message: format!(
                "document {dossier_path} was not extracted because it uses the legacy cipher {oid}; pass --allow-legacy-ciphers to decrypt it anyway"
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
