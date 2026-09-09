//! Making the text a dossier chose safe before it leaves the process.
//!
//! A dossier is attacker-controlled input. Its title, its document titles,
//! its MIME type halves, its object references, its transform names and the
//! `Id` attributes of its signatures are strings someone else wrote, and all
//! of them end up in two places: the JSON envelope, and — because the human
//! summary is rendered from that same envelope — a terminal, which reads more
//! than text. An unfiltered string there can move the cursor, repaint a line,
//! or reverse the reading order of what is printed around it, which is how a
//! `.txt` in a listing is really a `.exe`.
//!
//! The bounded XML parser already refuses the C0 and C1 control ranges, so
//! `ESC` cannot arrive through a dossier at all; the exposure this module
//! closes is the Unicode `Cf` class, where the bidirectional overrides live,
//! and length, since nothing in the format bounds a `subtype`.
//!
//! [`data`] is applied once, to the finished `data` value, so the envelope and
//! the human summary are covered by the same pass rather than by two filters
//! that could drift apart. The same filter as everywhere else does the work:
//! [`sanitize_display`] drops `Cc` and `Cf` and bounds what is left.

use openszigno_core::{MAX_DISPLAY_CHARS, sanitize_display};
use serde_json::Value;

/// The cap for a title, dossier or document.
///
/// Wider than [`MAX_DISPLAY_CHARS`], because a title is prose a person wrote
/// and real dossiers carry long ones: a court case title with parties and a
/// case number runs well past 128 characters, and cutting one short would
/// make the tool wrong about its input rather than safe with it. The author
/// crate refuses to *write* a title longer than 240 bytes, so 256 characters
/// is above anything openSzigno itself produces while still bounding what a
/// hostile dossier can put on one line.
pub(crate) const MAX_TITLE_CHARS: usize = 256;

/// The cap for a human message: a warning, an error, or a verifier check.
///
/// These are sentences this tool writes, not values a dossier chose, and the
/// longest of them already runs to about 200 characters. The bound is here so
/// that an input-derived fragment inside one cannot grow without limit, not to
/// shorten the sentence around it.
pub(crate) const MAX_MESSAGE_CHARS: usize = 512;

/// Sanitise every string in a finished `data` value in place.
///
/// Applied by the commands that read a dossier — `inspect`, `list`,
/// `validate-structure`, `extract` and `verify` — at the point where the value
/// is built, which is the one point both output channels pass through.
pub(crate) fn data(value: &mut Value) {
    sanitize_under(value, None);
}

/// Sanitise one human message: a warning's or an error's text.
pub(crate) fn message(text: &str) -> String {
    sanitize_display(text, MAX_MESSAGE_CHARS)
}

/// The recursive walk. An array inherits the key of the field that holds it,
/// so `"transforms": ["base64"]` is bounded as a `transforms` value.
fn sanitize_under(value: &mut Value, key: Option<&str>) {
    match value {
        Value::String(text) => {
            if let Some(limit) = limit_for(key) {
                let sanitized = sanitize_display(text, limit);
                if sanitized != *text {
                    *text = sanitized;
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_under(item, key);
            }
        }
        Value::Object(fields) => {
            for (name, item) in fields {
                sanitize_under(item, Some(name.as_str()));
            }
        }
        _ => {}
    }
}

/// The cap one field is held to, or `None` for a field left exactly as it is.
///
/// The default is [`MAX_DISPLAY_CHARS`]: long enough for a media type, an
/// algorithm URI, a signature `Id` or a date, short enough that no single
/// value a dossier chose can fill a screen.
fn limit_for(key: Option<&str>) -> Option<usize> {
    match key {
        // An extracted document's output filename, and the only string in any
        // envelope that has to match something outside it: the file on disk.
        // It is already safe — `openszigno_author::check_title` refuses a
        // title carrying a control, invisible or formatting character before
        // a name is derived from it, and bounds the result to 240 bytes — and
        // truncating it here would name a file that was never written.
        Some("path") => None,
        Some("title") => Some(MAX_TITLE_CHARS),
        Some("message" | "reason") => Some(MAX_MESSAGE_CHARS),
        _ => Some(MAX_DISPLAY_CHARS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[test]
    fn a_bidirectional_override_does_not_survive_anywhere_in_the_value() {
        let mut value = json!({
            "dossier": { "title": "OK\u{202e}txt.exe" },
            "documents": [{
                "title": "report\u{202e}fdp.exe",
                "mime_type": { "media_type": "te\u{200f}xt", "subtype": "pl\u{202d}ain" },
                "object_ref": "Object\u{2066}0",
                "transforms": ["base\u{202e}64"]
            }]
        });
        data(&mut value);
        assert_eq!(value["dossier"]["title"], "OKtxt.exe");
        assert_eq!(value["documents"][0]["title"], "reportfdp.exe");
        assert_eq!(value["documents"][0]["mime_type"]["media_type"], "text");
        assert_eq!(value["documents"][0]["mime_type"]["subtype"], "plain");
        assert_eq!(value["documents"][0]["object_ref"], "Object0");
        assert_eq!(value["documents"][0]["transforms"][0], "base64");
    }

    #[test]
    fn each_field_is_held_to_its_own_bound() {
        let long = "x".repeat(600);
        let mut value = json!({
            "title": long,
            "subtype": long,
            "message": long,
            "path": long,
        });
        data(&mut value);
        let chars = |field: &str| {
            value[field]
                .as_str()
                .expect("the field is a string")
                .chars()
                .count()
        };
        assert_eq!(chars("title"), MAX_TITLE_CHARS);
        assert_eq!(chars("subtype"), MAX_DISPLAY_CHARS);
        assert_eq!(chars("message"), MAX_MESSAGE_CHARS);
        assert_eq!(chars("path"), 600);
    }

    /// Numbers and booleans are the envelope's types, not text, and the pass
    /// must not turn one into the other.
    #[test]
    fn non_string_values_keep_their_type() {
        let mut value = json!({ "documents": 2, "verified": false, "creation_date": null });
        let before = value.clone();
        data(&mut value);
        assert_eq!(value, before);
    }

    #[test]
    fn a_message_is_bounded_rather_than_shortened() {
        let text = "document 0 was not extracted because it is encrypted";
        assert_eq!(message(text), text);
        assert_eq!(message("no\u{202e}pe"), "nope");
    }
}
