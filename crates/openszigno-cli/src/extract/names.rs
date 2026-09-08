//! Turning a document title into an output filename that is safe on every
//! filesystem, and keeping two documents from claiming one name.

use std::collections::HashSet;
use std::path::{Component, Path};

use openszigno_core::DetectedType;
use unicode_normalization::UnicodeNormalization;

use crate::response::CliError;

/// The key two names are compared on: NFC-normalised and case-folded, so a
/// case-insensitive filesystem cannot map two outputs onto one file.
pub(crate) fn name_key(name: &str) -> String {
    name.nfc().collect::<String>().to_lowercase()
}

/// Insert `-<index>` before the extension, so a repeated title still yields a
/// distinct, predictable filename.
pub(crate) fn deduplicated_name(name: &str, index: usize) -> String {
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
pub(crate) fn claim_name(names: &mut HashSet<String>, name: &str) -> Result<(), CliError> {
    if names.insert(name_key(name)) {
        return Ok(());
    }
    Err(CliError::unsafe_output(
        "output_name_collision",
        "two outputs resolve to the same name in one directory",
    ))
}

pub(crate) fn join_path(directory: &str, name: &str) -> String {
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
pub(crate) fn fallback_extension(
    document: &openszigno_core::Document,
    detected: DetectedType,
) -> Option<&'static str> {
    if document.mime_type.extension.is_some() {
        return None;
    }
    detected.preferred_extension()
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
pub(crate) fn safe_output_name(
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

#[cfg(test)]
mod tests {
    use super::*;

    use openszigno_core::Limits;

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
}
