//! The title rules a document must satisfy before it goes into a dossier.
//!
//! These are exactly the rules `openszigno extract` applies to a title before
//! it becomes a filename, factored out here so that both sides use one
//! implementation: a dossier this crate writes is always extractable, and a
//! title the extraction sanitizer refuses is refused at authoring time
//! instead, with the same reasoning.

use std::path::{Component, Path};

/// Why a title cannot be used as a filename.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TitleRejection {
    /// The title is empty, over-long, or holds a character that hides,
    /// reorders, or escapes.
    UnsafeTitle,
    /// The title is not one plain path component.
    UnsafePath,
    /// The title's stem is a reserved Windows device name.
    ReservedName,
}

/// The longest title accepted, before any extension is appended.
const MAX_TITLE_BYTES: usize = 240;

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

/// Whether `title` is a reserved Windows device name, on every platform.
fn is_reserved_device_name(title: &str) -> bool {
    let stem = title
        .split('.')
        .next()
        .unwrap_or(title)
        .to_ascii_uppercase();
    matches!(
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
    )
}

/// Check one document title against the extraction naming rules.
///
/// `title` is checked as given: a caller that accepts surrounding whitespace
/// trims it first, exactly as the extraction sanitizer does.
pub fn check_title(title: &str) -> Result<(), TitleRejection> {
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
        || title.len() > MAX_TITLE_BYTES
    {
        return Err(TitleRejection::UnsafeTitle);
    }
    let path = Path::new(title);
    if path.is_absolute()
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(TitleRejection::UnsafePath);
    }
    if is_reserved_device_name(title) {
        return Err(TitleRejection::ReservedName);
    }
    Ok(())
}

/// The extension the dossier may declare for `title`.
///
/// A declared extension must be a short ASCII alphanumeric suffix, because
/// that is all the extraction sanitizer accepts. Anything else is simply not
/// declared: the reader then falls back to content sniffing, which is a
/// better answer than a profile the reader would refuse.
pub fn declarable_extension(title: &str) -> Option<&str> {
    let extension = Path::new(title).extension()?.to_str()?;
    (!extension.is_empty()
        && extension.len() <= 16
        && extension
            .chars()
            .all(|character| character.is_ascii_alphanumeric()))
    .then_some(extension)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_title_is_accepted() {
        for title in ["hello.txt", "Report 2026.pdf", "no-dot", "console.txt"] {
            assert_eq!(check_title(title), Ok(()), "{title} must be accepted");
        }
    }

    #[test]
    fn a_title_that_hides_reorders_or_escapes_is_rejected() {
        for title in [
            "",
            ".",
            "..",
            ".hidden",
            "-rf",
            "a<b",
            "a>b",
            "a:b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
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
            "trailing ",
        ] {
            assert_eq!(
                check_title(title),
                Err(TitleRejection::UnsafeTitle),
                "{title:?} must be rejected"
            );
        }
        assert_eq!(
            check_title(&"a".repeat(MAX_TITLE_BYTES + 1)),
            Err(TitleRejection::UnsafeTitle)
        );
        assert_eq!(check_title(&"a".repeat(MAX_TITLE_BYTES)), Ok(()));
    }

    #[test]
    fn a_title_that_is_not_one_component_is_rejected() {
        for title in ["dir/file.txt", "dir\\file.txt", "../escape.txt"] {
            assert!(matches!(
                check_title(title),
                Err(TitleRejection::UnsafeTitle | TitleRejection::UnsafePath)
            ));
        }
    }

    #[test]
    fn a_reserved_device_name_is_rejected_on_every_platform() {
        for title in ["CON", "con", "nul.txt", "COM1", "lpt9.dat"] {
            assert_eq!(
                check_title(title),
                Err(TitleRejection::ReservedName),
                "{title} is a reserved device name"
            );
        }
    }

    #[test]
    fn only_a_short_ascii_alphanumeric_suffix_is_declarable() {
        assert_eq!(declarable_extension("hello.txt"), Some("txt"));
        assert_eq!(declarable_extension("archive.tar.gz"), Some("gz"));
        assert_eq!(declarable_extension("no-extension"), None);
        assert_eq!(declarable_extension("weird.t-x"), None);
        assert_eq!(declarable_extension("long.abcdefghijklmnopq"), None);
        assert_eq!(declarable_extension("accent.\u{e9}"), None);
    }
}
