//! Deriving the `es:MIME-Type` a document profile declares.
//!
//! The reader takes `type`, `subtype`, and `extension` straight out of the
//! profile, so the writer fills exactly those three fields. The extension is
//! the title's own suffix, and the media type comes either from the caller or
//! from the table below, which covers every category
//! `openszigno_core::sniff` can name plus the office and image types that
//! occur in practice. An extension outside it is refused rather than guessed:
//! a wrong declared type is worse than no dossier.

use openszigno_core::MimeType;

use crate::error::{Error, ErrorCode};
use crate::title::declarable_extension;

/// The media type the nested-dossier detection in `openszigno-core`
/// recognises, with the extension the same detection accepts.
pub const NESTED_DOSSIER_MEDIA_TYPE: &str = "application";
/// The subtype half of [`NESTED_DOSSIER_MEDIA_TYPE`].
pub const NESTED_DOSSIER_SUBTYPE: &str = "nldossier2";
/// The extension an embedded dossier is titled with.
pub const NESTED_DOSSIER_EXTENSION: &str = "dosszie";

/// Extension to media type. Lowercase keys; the lookup lowercases too.
const TABLE: &[(&str, &str, &str)] = &[
    ("csv", "text", "csv"),
    ("doc", "application", "msword"),
    (
        "docx",
        "application",
        "vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    ("dosszie", NESTED_DOSSIER_MEDIA_TYPE, NESTED_DOSSIER_SUBTYPE),
    ("es3", "application", "vnd.eszigno3+xml"),
    ("gif", "image", "gif"),
    ("htm", "text", "html"),
    ("html", "text", "html"),
    ("jpeg", "image", "jpeg"),
    ("jpg", "image", "jpeg"),
    ("json", "application", "json"),
    ("ods", "application", "vnd.oasis.opendocument.spreadsheet"),
    ("odt", "application", "vnd.oasis.opendocument.text"),
    ("pdf", "application", "pdf"),
    ("png", "image", "png"),
    ("rtf", "application", "rtf"),
    ("tif", "image", "tiff"),
    ("tiff", "image", "tiff"),
    ("txt", "text", "plain"),
    ("xls", "application", "vnd.ms-excel"),
    (
        "xlsx",
        "application",
        "vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    ("xml", "text", "xml"),
    ("zip", "application", "zip"),
];

/// Split a caller-supplied `type/subtype` into its two halves.
///
/// Only the essence is accepted: a parameter such as `; charset=utf-8` is not
/// part of what the profile declares, so it is a refusal rather than
/// something silently dropped.
fn split_essence(essence: &str) -> Result<(String, String), Error> {
    let invalid = || {
        Error::new(
            ErrorCode::InvalidMimeType,
            "a media type must be written as type/subtype",
        )
    };
    let (media_type, subtype) = essence.split_once('/').ok_or_else(invalid)?;
    let usable = |part: &str| {
        !part.is_empty()
            && part.len() <= 64
            && part.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+' | '_')
            })
    };
    if !usable(media_type) || !usable(subtype) {
        return Err(invalid());
    }
    Ok((
        media_type.to_ascii_lowercase(),
        subtype.to_ascii_lowercase(),
    ))
}

/// The media type registered for `extension`, if the table knows one.
fn lookup(extension: &str) -> Option<(&'static str, &'static str)> {
    let key = extension.to_ascii_lowercase();
    TABLE
        .iter()
        .find(|(candidate, _, _)| *candidate == key)
        .map(|(_, media_type, subtype)| (*media_type, *subtype))
}

/// The `es:MIME-Type` for a document titled `title`.
///
/// `declared` is the caller's `type/subtype`, when they gave one. Without it
/// the title's extension must be in the table; a document whose type cannot
/// be determined is refused, never guessed.
pub fn mime_for(title: &str, declared: Option<&str>) -> Result<MimeType, Error> {
    let extension = declarable_extension(title).map(str::to_owned);
    let (media_type, subtype) = match declared {
        Some(essence) => split_essence(essence)?,
        None => {
            let known = extension.as_deref().and_then(lookup).ok_or_else(|| {
                Error::new(
                    ErrorCode::UnknownMimeType,
                    "no media type is registered for this document's extension; \
                     give one as PATH::TITLE::TYPE/SUBTYPE",
                )
            })?;
            (known.0.to_owned(), known.1.to_owned())
        }
    };
    Ok(MimeType {
        media_type,
        subtype,
        extension,
        charset: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_and_holds_every_sniffable_extension() {
        let keys: Vec<&str> = TABLE.iter().map(|(key, _, _)| *key).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "keep the table in extension order");
        for extension in ["pdf", "html", "xml", "es3", "zip", "txt"] {
            assert!(
                lookup(extension).is_some(),
                "{extension} is a sniffable extension and must have a type"
            );
        }
    }

    #[test]
    fn a_known_extension_derives_the_type_and_is_declared() {
        let mime = mime_for("hello.txt", None).expect("txt is known");
        assert_eq!(mime.essence(), "text/plain");
        assert_eq!(mime.extension.as_deref(), Some("txt"));
        assert_eq!(mime.charset, None);
        assert_eq!(
            mime_for("scan.JPG", None).expect("jpg is known").essence(),
            "image/jpeg"
        );
    }

    #[test]
    fn an_unknown_extension_is_refused_unless_a_type_is_given() {
        let error = mime_for("payload.bin", None).expect_err("bin is not in the table");
        assert_eq!(error.code(), ErrorCode::UnknownMimeType);
        let error = mime_for("payload", None).expect_err("no extension at all");
        assert_eq!(error.code(), ErrorCode::UnknownMimeType);
        let mime = mime_for("payload.bin", Some("application/octet-stream"))
            .expect("an explicit type is enough");
        assert_eq!(mime.essence(), "application/octet-stream");
        assert_eq!(mime.extension.as_deref(), Some("bin"));
    }

    #[test]
    fn a_malformed_media_type_is_refused() {
        for essence in [
            "text",
            "/plain",
            "text/",
            "text/plain; charset=utf-8",
            "te xt/plain",
            "",
        ] {
            let error =
                mime_for("payload.bin", Some(essence)).expect_err("{essence} must be refused");
            assert_eq!(error.code(), ErrorCode::InvalidMimeType, "{essence}");
        }
    }

    #[test]
    fn an_undeclarable_extension_is_left_out_of_the_profile() {
        let mime =
            mime_for("archive.t-x", Some("application/octet-stream")).expect("the type is given");
        assert_eq!(mime.extension, None);
    }
}
