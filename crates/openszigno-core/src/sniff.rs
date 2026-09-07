//! Cheap content sniffing for decoded payloads.
//!
//! Declared MIME types in real dossiers are unreliable, so a caller needs a
//! hint about what a payload actually is. The sniffer looks at a bounded
//! prefix of the bytes only, never allocates a copy of the payload, and never
//! reports anything about the content beyond the coarse category below.

use serde::Serialize;

/// Coarse content category of a decoded payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedType {
    Pdf,
    Html,
    Xml,
    Dossier,
    Zip,
    Text,
    Binary,
}

impl DetectedType {
    /// The stable string used in the JSON protocol.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Html => "html",
            Self::Xml => "xml",
            Self::Dossier => "dossier",
            Self::Zip => "zip",
            Self::Text => "text",
            Self::Binary => "binary",
        }
    }

    /// The filename extension a caller may append when nothing else is known.
    ///
    /// `Binary` has none: an unknown byte stream must not be given a
    /// misleading suffix.
    pub const fn preferred_extension(self) -> Option<&'static str> {
        match self {
            Self::Pdf => Some("pdf"),
            Self::Html => Some("html"),
            Self::Xml => Some("xml"),
            Self::Dossier => Some("es3"),
            Self::Zip => Some("zip"),
            Self::Text => Some("txt"),
            Self::Binary => None,
        }
    }
}

/// Bytes examined for markup and for the text/binary decision.
const SNIFF_WINDOW: usize = 4096;
/// Bytes within which a leading HTML tag still counts as HTML.
const HTML_WINDOW: usize = 1024;

/// Classify a decoded payload from a bounded prefix of its bytes.
pub fn sniff(bytes: &[u8]) -> DetectedType {
    if bytes.starts_with(b"%PDF") {
        return DetectedType::Pdf;
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return DetectedType::Zip;
    }
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let markup = trim_ascii_start(body);
    if markup.starts_with(b"<")
        && let Some(kind) = sniff_markup(markup)
    {
        return kind;
    }
    if is_text(bytes) {
        DetectedType::Text
    } else {
        DetectedType::Binary
    }
}

/// Walk the prolog of an XML-looking prefix until the first element start tag
/// and classify it. Returns `None` when the prefix is not markup after all.
fn sniff_markup(input: &[u8]) -> Option<DetectedType> {
    let window = &input[..input.len().min(SNIFF_WINDOW)];
    let mut saw_declaration = false;
    let mut i = 0usize;

    while i < window.len() {
        if window[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if window[i] != b'<' {
            break;
        }
        let rest = &window[i..];
        if rest.starts_with(b"<!--") {
            match skip_past(rest, 4, b"-->") {
                Some(next) => i += next,
                None => break,
            }
            continue;
        }
        if rest.starts_with(b"<?") {
            if starts_with_ignore_case(&rest[2..], b"xml") {
                saw_declaration = true;
            }
            match skip_past(rest, 2, b"?>") {
                Some(next) => i += next,
                None => break,
            }
            continue;
        }
        if rest.starts_with(b"<!") {
            if starts_with_ignore_case(&rest[2..], b"doctype")
                && starts_with_ignore_case(trim_ascii_start(&rest[9..]), b"html")
            {
                return Some(DetectedType::Html);
            }
            match skip_past(rest, 2, b">") {
                Some(next) => i += next,
                None => break,
            }
            continue;
        }
        // A real element start tag: its local name decides the category.
        return match element_kind(&rest[1..])? {
            // A leading HTML tag only counts near the start of the payload.
            RootKind::Html if i < HTML_WINDOW => Some(DetectedType::Html),
            RootKind::Dossier => Some(DetectedType::Dossier),
            RootKind::Html | RootKind::Other => Some(DetectedType::Xml),
        };
    }

    // The prefix was a declaration or comment with no element in the window.
    saw_declaration.then_some(DetectedType::Xml)
}

/// What the root element's local name says the payload is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootKind {
    Html,
    Dossier,
    Other,
}

/// Classify the qualified name that follows `<`.
///
/// The comparison is byte-wise on purpose: an ISO-8859-2 document is still
/// markup, and its element names may hold bytes that are not valid UTF-8, so
/// the markup decision must never depend on UTF-8 validity. `None` means the
/// `<` starts no name at all, and the payload is not markup.
fn element_kind(bytes: &[u8]) -> Option<RootKind> {
    let first = *bytes.first()?;
    if !(first.is_ascii_alphabetic() || first == b'_' || first >= 0x80) {
        return None;
    }
    let end = bytes
        .iter()
        .position(|byte| {
            byte.is_ascii_whitespace() || *byte == b'>' || *byte == b'/' || *byte == b'='
        })
        .unwrap_or(bytes.len());
    let name = &bytes[..end];
    let local = name
        .iter()
        .rposition(|byte| *byte == b':')
        .map_or(name, |colon| &name[colon + 1..]);
    if [b"html".as_slice(), b"head", b"body", b"meta"]
        .iter()
        .any(|candidate| local.eq_ignore_ascii_case(candidate))
    {
        return Some(RootKind::Html);
    }
    if local == b"Dossier" {
        return Some(RootKind::Dossier);
    }
    Some(RootKind::Other)
}

/// Index just past `terminator`, searching from `from` inside `bytes`.
fn skip_past(bytes: &[u8], from: usize, terminator: &[u8]) -> Option<usize> {
    if from >= bytes.len() {
        return None;
    }
    bytes[from..]
        .windows(terminator.len())
        .position(|window| window == terminator)
        .map(|position| from + position + terminator.len())
}

fn starts_with_ignore_case(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// Valid UTF-8 with no NUL and no control characters other than whitespace,
/// judged on a bounded prefix. A multi-byte character cut by the window
/// boundary does not make the payload binary.
fn is_text(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(SNIFF_WINDOW)];
    let text = match std::str::from_utf8(window) {
        Ok(text) => text,
        Err(error) if error.error_len().is_none() && window.len() == SNIFF_WINDOW => {
            // Only a truncated final character; judge the valid prefix.
            std::str::from_utf8(&window[..error.valid_up_to()]).unwrap_or("")
        }
        Err(_) => return false,
    };
    text.chars()
        .all(|character| !character.is_control() || character.is_whitespace())
}
