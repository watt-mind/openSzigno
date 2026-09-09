//! Making a string that came from somewhere untrusted safe to print.
//!
//! Element names out of a signature, credential identifiers out of a remote
//! signing service, error strings a provider wrote: none of them are typed by
//! the operator, and all of them end up in a terminal, in an error message, or
//! in the JSON envelope. A terminal reads more than text, so a string that
//! reaches one unfiltered can move the cursor, repaint a line, or reorder what
//! is displayed around it.
//!
//! [`sanitize_display`] is the one filter for all of them. It drops every
//! Unicode `Cc` (control) and `Cf` (format, which is where the bidirectional
//! overrides live) character and bounds the result, so what is printed is the
//! visible content of the value and no more than the caller asked for.

/// The elision marker appended to a value the cap cut short. ASCII, so that it
/// survives every console encoding the tool runs on.
const ELISION: &str = "...";

/// The cap used where a caller has no reason to pick its own: long enough for
/// a credential identifier or an element name, short enough that no single
/// value can fill a screen.
pub const MAX_DISPLAY_CHARS: usize = 128;

/// Strip the characters a terminal would act on rather than show, and bound
/// the result to `limit` characters.
///
/// Dropped, never escaped: `Cc` (the C0 and C1 control ranges, which is where
/// `ESC` and therefore every ANSI sequence lives) and `Cf` (format
/// characters, which is where the bidirectional overrides, the zero-width
/// joiners and the byte-order mark live). Escaping them would keep an
/// attacker-chosen string in the output under a different spelling; dropping
/// them keeps only what a reader can see.
///
/// The returned string is never longer than `limit` characters: a value that
/// was cut short ends in `...`, inside the cap rather than beyond it.
#[must_use]
pub fn sanitize_display(value: &str, limit: usize) -> String {
    let mut kept: Vec<char> = value
        .chars()
        .filter(|character| !is_hidden(*character))
        .take(limit.saturating_add(1))
        .collect();
    if kept.len() <= limit {
        return kept.into_iter().collect();
    }
    let marker = ELISION.chars().count();
    if limit <= marker {
        kept.truncate(limit);
        return kept.into_iter().collect();
    }
    kept.truncate(limit - marker);
    let mut text: String = kept.into_iter().collect();
    text.push_str(ELISION);
    text
}

/// Whether a character is one a terminal acts on rather than shows.
fn is_hidden(character: char) -> bool {
    character.is_control() || is_format(character)
}

/// The Unicode `Cf` ranges, spelled out rather than pulled in as a dependency:
/// the table is small, it changes rarely, and a missed addition costs one
/// invisible character rather than a control sequence.
const FORMAT_RANGES: &[(char, char)] = &[
    ('\u{00ad}', '\u{00ad}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061c}', '\u{061c}'),
    ('\u{06dd}', '\u{06dd}'),
    ('\u{070f}', '\u{070f}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08e2}', '\u{08e2}'),
    ('\u{180e}', '\u{180e}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{202a}', '\u{202e}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{fff9}', '\u{fffb}'),
    ('\u{110bd}', '\u{110bd}'),
    ('\u{110cd}', '\u{110cd}'),
    ('\u{13430}', '\u{1343f}'),
    ('\u{1bca0}', '\u{1bca3}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0001}', '\u{e0001}'),
    ('\u{e0020}', '\u{e007f}'),
];

fn is_format(character: char) -> bool {
    FORMAT_RANGES
        .iter()
        .any(|(first, last)| character >= *first && character <= *last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_value_passes_through_unchanged() {
        assert_eq!(sanitize_display("cred-1a2b3c", 64), "cred-1a2b3c");
        assert_eq!(sanitize_display("", 64), "");
    }

    #[test]
    fn an_ansi_escape_sequence_does_not_survive() {
        let value = "\u{1b}[2J\u{1b}[31mcred\u{7}-1\u{9b}m";
        let sanitized = sanitize_display(value, 64);
        assert_eq!(sanitized, "[2J[31mcred-1m");
        assert!(!sanitized.contains('\u{1b}'));
        assert!(!sanitized.contains('\u{9b}'));
    }

    #[test]
    fn a_bidirectional_override_does_not_survive() {
        let value = "cred\u{202e}drowssap\u{202c}\u{200f}-1\u{feff}";
        let sanitized = sanitize_display(value, 64);
        assert_eq!(sanitized, "creddrowssap-1");
        assert!(!sanitized.chars().any(is_format));
    }

    #[test]
    fn a_long_value_is_cut_short_inside_the_cap() {
        let sanitized = sanitize_display(&"x".repeat(400), 16);
        assert_eq!(sanitized, "xxxxxxxxxxxxx...");
        assert_eq!(sanitized.chars().count(), 16);
    }

    #[test]
    fn a_value_exactly_at_the_cap_keeps_every_character() {
        let sanitized = sanitize_display(&"x".repeat(16), 16);
        assert_eq!(sanitized.chars().count(), 16);
        assert!(!sanitized.contains(ELISION));
    }

    #[test]
    fn a_cap_too_small_for_the_marker_still_holds() {
        assert_eq!(sanitize_display("abcdef", 2), "ab");
        assert_eq!(sanitize_display("abcdef", 0), "");
    }

    /// The cap counts characters, so a multi-byte value is not cut mid-code
    /// point and the count is what a reader would count.
    #[test]
    fn the_cap_counts_characters_rather_than_bytes() {
        let sanitized = sanitize_display("árvíztűrő tükörfúrógép", 8);
        assert_eq!(sanitized.chars().count(), 8);
        assert_eq!(sanitized, "árvíz...");
    }
}
