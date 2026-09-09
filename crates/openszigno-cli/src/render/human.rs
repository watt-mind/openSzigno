//! The human-readable summary each command prints when `--json` is absent.

use std::io::{self, Write};

use openszigno_core::{MAX_DISPLAY_CHARS, sanitize_display};
use serde_json::Value;

use crate::render::write_diagnostic;
use crate::response::Response;

/// Print the claimed signature inventory, one line per signature and one per
/// container timestamp.
///
/// Every line starts with `(unverified)`, because nothing on it was checked:
/// these are the dossier's own claims about its signature material, read out
/// of the XML at parse time.
fn write_signature_inventory(out: &mut impl Write, inventory: &Value) -> io::Result<()> {
    let signatures = inventory["signatures"]
        .as_array()
        .map_or(&[][..], |items| items);
    let timestamps = inventory["timestamps"]
        .as_array()
        .map_or(&[][..], |items| items);
    if signatures.is_empty() && timestamps.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "Signature inventory (claimed by the dossier; nothing below was verified):"
    )?;
    for (index, signature) in signatures.iter().enumerate() {
        let mut line = format!(
            "(unverified) signature {index}: placement={}",
            display_json_string(&signature["placement"])
        );
        if let Some(document) = signature["document_index"].as_u64() {
            line.push_str(&format!(", document={document}"));
        }
        if let Some(id) = signature["id"].as_str() {
            line.push_str(&format!(", id={id}"));
        }
        if let Some(parent) = signature["parent_signature_id"].as_str() {
            line.push_str(&format!(", inside={parent}"));
        }
        line.push_str(&format!(", references={}", signature["reference_count"]));
        let properties = join_json_strings(&signature["xades_properties"]);
        if !properties.is_empty() {
            line.push_str(&format!(", xades={properties}"));
        }
        // Claimed roles, when the signature states any. An AVDH-authenticated
        // dossier carries the citizen's asserted identity here, and it is a
        // claim like every other line: nothing on it was checked.
        let roles = join_json_strings(&signature["claimed_roles"]);
        if !roles.is_empty() {
            line.push_str(&format!(", claimed roles={roles}"));
        }
        let evidence = &signature["evidence"];
        line.push_str(&format!(
            ", certificates={}, crls={}, ocsp={}, signature-timestamps={}, archive-timestamps={}",
            evidence["certificates"],
            evidence["crls"],
            evidence["ocsp_responses"],
            evidence["signature_timestamps"],
            evidence["archive_timestamps"]
        ));
        if let Some(claimed) = signature["claimed_signing_time"].as_str() {
            line.push_str(&format!(", claimed signing time={claimed}"));
        }
        writeln!(out, "{line}")?;
    }
    for (index, timestamp) in timestamps.iter().enumerate() {
        let mut line = format!(
            "(unverified) timestamp {index}: placement={}",
            display_json_string(&timestamp["placement"])
        );
        if let Some(document) = timestamp["document_index"].as_u64() {
            line.push_str(&format!(", document={document}"));
        }
        line.push_str(&format!(", includes={}", timestamp["include_count"]));
        line.push_str(if timestamp["has_token"] == Value::Bool(true) {
            ", token=present"
        } else {
            ", token=absent"
        });
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// Join an array of JSON strings for a human line. The values come from the
/// core inventory, which only ever emits plain element names.
fn join_json_strings(value: &Value) -> String {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("+")
        })
        .unwrap_or_default()
}

pub(crate) fn write_human_success(command: &str, response: &Response) -> io::Result<()> {
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
            write_signature_inventory(&mut out, &dossier["signature_inventory"])?;
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
                let encrypted = if document["encrypted"] == Value::Bool(true) {
                    " | encrypted"
                } else {
                    ""
                };
                writeln!(
                    out,
                    "[{}] {} | {}/{} | {} B | {}{}{}",
                    document["index"],
                    display_json_string(&document["title"]),
                    display_json_string(&document["mime_type"]["media_type"]),
                    display_json_string(&document["mime_type"]["subtype"]),
                    display_source_size(&document["source_size"]),
                    document["transforms"],
                    encrypted,
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
            // Document coverage: which documents the signatures actually
            // cover. Kept apart from the verdict lines above, because "this
            // content is signed" and "that signature verifies" are different
            // questions. Titles never appear here.
            for document in data["documents"].as_array().into_iter().flatten() {
                let name = document["index"].as_u64().map_or_else(
                    || "document (not modelled)".to_owned(),
                    |index| format!("document {index}"),
                );
                let by: Vec<String> = document["covered_by"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|entry| {
                        format!(
                            "signature {} {}",
                            entry["signature_index"],
                            display_json_string(&entry["via"])
                        )
                    })
                    .collect();
                let by = if by.is_empty() {
                    String::new()
                } else {
                    format!(" by {}", by.join(", "))
                };
                writeln!(
                    out,
                    "{name}: {}{by}{}",
                    display_json_string(&document["coverage"]),
                    if document["nested_dossier"] == Value::Bool(true) {
                        " (an embedded dossier; its own inner signatures are not verified by this run)"
                    } else {
                        ""
                    }
                )?;
            }
            for signature in data["signatures"].as_array().into_iter().flatten() {
                // A countersignature attests another signature, not the
                // payload, so the line says which one rather than leaving a
                // reader to infer it from the placement alone.
                let countersigned: Vec<String> = signature["parent_signature_index"]
                    .as_u64()
                    .map(|index| vec![index.to_string()])
                    .unwrap_or_else(|| {
                        signature["countersigns"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .map(std::string::ToString::to_string)
                            .collect()
                    });
                let role = if signature["role"] == Value::String("countersignature".to_owned())
                    && !countersigned.is_empty()
                {
                    format!(
                        " (countersignature of signature {})",
                        countersigned.join(", ")
                    )
                } else {
                    String::new()
                };
                writeln!(
                    out,
                    "[{}] {} signature: {}{role}",
                    signature["index"],
                    display_json_string(&signature["placement"]),
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
        "create" => {
            writeln!(
                out,
                "Created {} ({} B, {} document(s)).",
                display_json_string(&response.data["output"]),
                response.data["bytes"],
                response.data["documents"].as_array().map_or(0, Vec::len)
            )?;
            for document in response.data["documents"].as_array().into_iter().flatten() {
                let nested = if document["nested_dossier"] == Value::Bool(true) {
                    " | nested dossier"
                } else {
                    ""
                };
                let encrypted = if document["encrypted"] == Value::Bool(true) {
                    " | encrypted"
                } else {
                    ""
                };
                writeln!(
                    out,
                    "[{}] {} | {}/{} | {} B | {}{}{}",
                    document["index"],
                    display_json_string(&document["title"]),
                    display_json_string(&document["mime_type"]["media_type"]),
                    display_json_string(&document["mime_type"]["subtype"]),
                    display_source_size(&document["source_size"]),
                    document["transforms"],
                    encrypted,
                    nested
                )?;
            }
            writeln!(
                out,
                "The dossier is unsigned: creating it proves nothing about its contents."
            )?;
        }
        "sign" => {
            let signatures = response.data["signatures"]
                .as_array()
                .map_or(&[][..], |items| items);
            writeln!(
                out,
                "Signed {} ({} B, {} signature(s)).",
                display_json_string(&response.data["output"]),
                response.data["bytes"],
                signatures.len()
            )?;
            for signature in signatures {
                let mut line = format!(
                    "{} | scope={} | {}",
                    display_json_string(&signature["id"]),
                    display_json_string(&signature["scope"]),
                    display_json_string(&signature["algorithm"])
                );
                if let Some(index) = signature["document_index"].as_u64() {
                    line.push_str(&format!(" | document={index}"));
                }
                line.push_str(&format!(
                    " | signing time={}",
                    display_json_string(&signature["signing_time"])
                ));
                line.push_str(if signature["timestamped"] == Value::Bool(true) {
                    " | timestamped"
                } else {
                    " | no timestamp"
                });
                // Which backend held the key. A remote one also names the
                // credential, because that is what says whose certificate
                // signed; the token that reached it never appears anywhere.
                if let Some(who) = signature["signer"].as_str() {
                    line.push_str(&format!(" | signer={who}"));
                }
                // Sanitised again on the way out. The envelope already holds
                // a sanitised value, but a terminal is where a control
                // sequence would act, so nothing a service chose reaches one
                // unfiltered on the strength of having been filtered earlier.
                if let Some(credential) = signature["credential_id"].as_str() {
                    let credential = sanitize_display(credential, MAX_DISPLAY_CHARS);
                    line.push_str(&format!(" | credential={credential}"));
                }
                writeln!(out, "{line}")?;
            }
            writeln!(
                out,
                "Signing verified nothing. Run `openszigno verify` with your own trust material to judge these signatures."
            )?;
        }
        "timestamp" => {
            let timestamps = response.data["timestamps"]
                .as_array()
                .map_or(&[][..], |items| items);
            writeln!(
                out,
                "Timestamped {} ({} B, {} timestamp(s)).",
                display_json_string(&response.data["output"]),
                response.data["bytes"],
                timestamps.len()
            )?;
            for timestamp in timestamps {
                let mut line = format!(
                    "{} | scope={}",
                    display_json_string(&timestamp["id"]),
                    display_json_string(&timestamp["scope"])
                );
                if let Some(index) = timestamp["document_index"].as_u64() {
                    line.push_str(&format!(" | document={index}"));
                }
                // The authority's own claim about when it saw the imprint.
                // Nothing in this run checked it.
                if let Some(gen_time) = timestamp["gen_time"].as_str() {
                    line.push_str(&format!(" | genTime={gen_time}"));
                }
                writeln!(out, "{line}")?;
            }
            writeln!(
                out,
                "Timestamping verified nothing. Run `openszigno verify` with your own trust material to judge this timestamp."
            )?;
        }
        "csc-login" => {
            let data = &response.data;
            writeln!(
                out,
                "Logged in to {}.",
                display_json_string(&data["base_url"])
            )?;
            writeln!(
                out,
                "Token written to {} (mode 0600 on Unix; it is never printed).",
                display_json_string(&data["token_file"])
            )?;
            let expiry = data["expires_at"]
                .as_str()
                .map_or_else(|| "not stated by the service".to_owned(), str::to_owned);
            writeln!(
                out,
                "Expires: {expiry} | refresh token stored: {}",
                data["refresh_token_stored"]
            )?;
            writeln!(
                out,
                "Service: specs={} | supportsRar={}",
                display_json_string(&data["specs"]),
                data["supports_rar"]
            )?;
            if let Some(credential) = data["credential"].as_object() {
                writeln!(
                    out,
                    "Credential {} | auth mode={} | interactive signature round required: {}",
                    display_json_string(&credential["credential_id"]),
                    display_json_string(&credential["auth_mode"]),
                    credential["interactive_signature_required"]
                )?;
            }
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

/// One string field of the envelope, as a human line shows it.
///
/// The value is printed as it stands, because the envelope it comes from was
/// already sanitised: every command that reads a dossier runs
/// [`crate::sanitize::data`] over its `data` before the response is built, so
/// what arrives here carries no `Cc` or `Cf` character and is already bounded.
/// Filtering again here would be a second filter to keep in step with the
/// first; the one pass covers both channels precisely because this renderer
/// reads the same value the JSON envelope does.
fn display_json_string(value: &Value) -> String {
    value.as_str().unwrap_or("<missing>").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[test]
    fn a_missing_json_string_is_rendered_as_a_placeholder() {
        assert_eq!(display_json_string(&json!("title")), "title");
        assert_eq!(display_json_string(&Value::Null), "<missing>");
        assert_eq!(display_json_string(&json!(7)), "<missing>");
    }
}
