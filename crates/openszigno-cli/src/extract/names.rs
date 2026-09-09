//! Turning a document title into an output filename that is safe on every
//! filesystem, and keeping two documents from claiming one name.

use std::collections::HashSet;
use std::path::Path;

use openszigno_author::{TitleRejection, check_title};
use openszigno_core::DetectedType;
use unicode_normalization::UnicodeNormalization;

use crate::response::CliError;

/// The key two names are compared on: NFC-normalised and case-folded, so a
/// case-insensitive filesystem cannot map two outputs onto one file.
pub(crate) fn name_key(name: &str) -> String {
    name.nfc().collect::<String>().to_lowercase()
}

/// How many deduplicated candidates are tried before a name is given up on.
///
/// A title crafted to collide with the name deduplication itself produces
/// would otherwise abort the whole run, so the counter keeps going; it is
/// bounded because a run that has tried this many names is not going to find a
/// free one, and an unbounded search is its own denial of service.
pub(crate) const MAX_DEDUPLICATION_ATTEMPTS: u32 = 64;

/// Insert a distinguishing suffix before the extension, so a repeated title
/// still yields a distinct, predictable filename.
///
/// `attempt` counts from 1. The first candidate is `stem-<index>.<ext>`, which
/// is what a repeated title has always produced; a title crafted to be exactly
/// that name is why there is a second, third and further candidate,
/// `stem-<index>-2.<ext>` onwards.
pub(crate) fn deduplicated_name(name: &str, index: usize, attempt: u32) -> String {
    let suffix = match attempt {
        0 | 1 => format!("-{index}"),
        other => format!("-{index}-{other}"),
    };
    let path = Path::new(name);
    match (
        path.file_stem().and_then(|stem| stem.to_str()),
        path.extension().and_then(|extension| extension.to_str()),
    ) {
        (Some(stem), Some(extension)) if !stem.is_empty() => {
            format!("{stem}{suffix}.{extension}")
        }
        _ => format!("{name}{suffix}"),
    }
}

/// Take a name in one directory, reporting whether it was free.
pub(crate) fn try_claim_name(names: &mut HashSet<String>, name: &str) -> bool {
    names.insert(name_key(name))
}

/// Two documents whose names still collide after every deduplicated candidate
/// was tried.
pub(crate) fn name_collision() -> CliError {
    CliError::unsafe_output(
        "output_name_collision",
        "two outputs resolve to the same name in one directory",
    )
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

/// Derive the output filename from the document title.
///
/// `fallback` is the extension suggested by content sniffing; it is used only
/// when the title carries no extension and the dossier declares none.
pub(crate) fn safe_output_name(
    document: &openszigno_core::Document,
    fallback: Option<&str>,
) -> Result<String, CliError> {
    let title = document.title.trim();
    // The rules live in `openszigno-author`, so that a title this command
    // would refuse to write is one `openszigno create` refuses to put into a
    // dossier in the first place.
    check_title(title).map_err(|rejection| {
        let reason = match rejection {
            TitleRejection::UnsafeTitle => "has an unsafe output title",
            TitleRejection::UnsafePath => "has an unsafe output path",
            TitleRejection::ReservedName => "uses a reserved output title",
        };
        CliError::unsafe_output(
            "unsafe_output_name",
            format!("document {} {reason}", document.index),
        )
    })?;

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
        assert!(try_claim_name(&mut names, "Report.txt"));
        // The comparison is case-insensitive: a case-insensitive filesystem
        // must not be able to map two outputs onto one file.
        assert!(!try_claim_name(&mut names, "report.TXT"));
        let error = name_collision();
        assert_eq!(error.code, "output_name_collision");
        assert_eq!(error.exit, 5);
    }

    /// The deduplicated candidates are a sequence, not one name: the first is
    /// the `stem-<index>` form a repeated title has always produced, and the
    /// ones after it carry an increasing counter, which is what keeps a title
    /// crafted to spell the first candidate from aborting the run.
    #[test]
    fn the_deduplicated_candidates_count_upwards() {
        assert_eq!(deduplicated_name("report.txt", 3, 1), "report-3.txt");
        assert_eq!(deduplicated_name("report.txt", 3, 2), "report-3-2.txt");
        assert_eq!(deduplicated_name("report.txt", 3, 64), "report-3-64.txt");
        // A name with no extension keeps the suffix at its end.
        assert_eq!(deduplicated_name("report", 3, 1), "report-3");
        assert_eq!(deduplicated_name("report", 3, 5), "report-3-5");
        // A dotfile-looking name has no stem to split, so it is suffixed whole.
        assert_eq!(deduplicated_name(".env", 0, 2), ".env-0-2");
    }
}
