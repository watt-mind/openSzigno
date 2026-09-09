//! The names a signature writes, and what a dossier is allowed to contribute
//! to the XML this module signs.
//!
//! A signature is assembled as text, and several of the values in it come
//! from the dossier being signed rather than from this crate: the `OBJREF`
//! and `Id` attributes a reference points at, the media type an
//! `xades:DataObjectFormat` declares, and the namespace URI the signature
//! profile object declares. A dossier is untrusted input, so those values are
//! checked here before anything is rendered, and escaped again at every
//! interpolation.
//!
//! The two halves are deliberately both present. The checks keep a hostile
//! dossier from choosing the reference set or the signed properties the
//! operator's key ends up signing; the escaping is the guarantee that no
//! dossier-derived string can reach signature XML unescaped, whatever a later
//! change adds to the rendering.
//!
//! The identifiers a signature introduces live here too, because choosing
//! them is the other half of the same question: which names end up in the
//! document, and which of them the dossier has already claimed.

use super::error::{SignError, SignErrorCode};
use super::{dsig, xades};

/// The longest identifier this module will write into a reference.
///
/// Nothing in the format needs more, and a bound keeps a pathological `Id`
/// from being copied into four references and a `Target` attribute.
const MAX_ID_LENGTH: usize = 256;

/// The longest namespace URI a signature profile object will declare.
const MAX_NAMESPACE_LENGTH: usize = 512;

fn not_signable(reason: &str) -> SignError {
    SignError::new(
        SignErrorCode::DocumentNotSignable,
        format!("this dossier cannot be signed: {reason}"),
    )
}

/// XML 1.0 `NameStartChar`, without the colon a `NCName` excludes.
fn is_name_start(character: char) -> bool {
    matches!(character,
        'A'..='Z'
        | '_'
        | 'a'..='z'
        | '\u{c0}'..='\u{d6}'
        | '\u{d8}'..='\u{f6}'
        | '\u{f8}'..='\u{2ff}'
        | '\u{370}'..='\u{37d}'
        | '\u{37f}'..='\u{1fff}'
        | '\u{200c}'..='\u{200d}'
        | '\u{2070}'..='\u{218f}'
        | '\u{2c00}'..='\u{2fef}'
        | '\u{3001}'..='\u{d7ff}'
        | '\u{f900}'..='\u{fdcf}'
        | '\u{fdf0}'..='\u{fffd}'
        | '\u{10000}'..='\u{effff}')
}

/// XML 1.0 `NameChar`, without the colon a `NCName` excludes.
fn is_name_char(character: char) -> bool {
    is_name_start(character)
        || matches!(character,
            '-' | '.'
            | '0'..='9'
            | '\u{b7}'
            | '\u{300}'..='\u{36f}'
            | '\u{203f}'..='\u{2040}')
}

/// Whether `value` is an XML `NCName`, which is what an `Id` has to be for a
/// same-document `#id` reference to name it at all.
pub(crate) fn is_ncname(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some(first) if is_name_start(first)) && characters.all(is_name_char)
}

/// Refuse an identifier that could not appear in a well-formed reference.
///
/// `what` names the attribute, never its value: a refusal says which input is
/// unusable and quotes none of the dossier back.
pub(crate) fn check_id(what: &str, value: &str) -> Result<(), SignError> {
    if value.len() > MAX_ID_LENGTH {
        return Err(not_signable(&format!(
            "an {what} it would have to reference is longer than {MAX_ID_LENGTH} characters"
        )));
    }
    if !is_ncname(value) {
        return Err(not_signable(&format!(
            "an {what} it would have to reference is not an XML NCName"
        )));
    }
    Ok(())
}

/// Refuse a declared media type outside the RFC 2045 token characters.
///
/// The rule is the writer's own, in [`crate::mime`]: both halves non-empty,
/// at most 64 characters, and nothing but ASCII alphanumerics and `.-+_`.
pub(crate) fn check_mime_essence(value: &str) -> Result<(), SignError> {
    let usable = value.split_once('/').is_some_and(|(media_type, subtype)| {
        crate::mime::is_essence_token(media_type) && crate::mime::is_essence_token(subtype)
    });
    if usable {
        return Ok(());
    }
    Err(not_signable(
        "a document declares a media type that is not written as type/subtype \
         in the characters a media type is allowed to use",
    ))
}

/// Refuse a namespace URI that could not appear in a namespace declaration.
///
/// The markup delimiters and both quote characters are the ones escaping
/// would otherwise have to carry; a control character is refused because
/// nothing legitimate declares one and the canonical form of an attribute
/// value rewrites it.
pub(crate) fn check_namespace(value: &str) -> Result<(), SignError> {
    if value.is_empty() || value.len() > MAX_NAMESPACE_LENGTH {
        return Err(not_signable(
            "its namespace URI is empty or implausibly long",
        ));
    }
    if value.chars().any(|character| {
        matches!(character, '<' | '>' | '"' | '\'' | '&') || character.is_control()
    }) {
        return Err(not_signable(
            "its namespace URI holds a markup delimiter, a quote character, or a \
             control character",
        ));
    }
    Ok(())
}

/// How many signatures may share one base identifier.
///
/// A dossier that already holds this many co-signatures of one document is
/// refused rather than searched further; nothing legitimate reaches it.
const MAX_SHARED_IDENTIFIERS: usize = 64;

/// Every `Id` one signature would introduce, given the `Id` of the signature
/// itself.
fn identifiers(id: &str, reference_names: &[&str]) -> Vec<String> {
    let mut used = vec![
        id.to_owned(),
        format!("signed-props-{id}"),
        format!("xades-{id}"),
        format!("sigprof-{id}"),
        xades::signature_profile_object_id(id),
    ];
    used.extend(
        reference_names
            .iter()
            .map(|name| format!("ref-{id}-{name}")),
    );
    used
}

/// The `Id` this signature gets.
///
/// Every identifier is derived from the document index, so a document this
/// tool has already signed would collide with itself. Co-signing is
/// something the format allows and this tool supports, so a base identifier
/// already in the dossier is disambiguated (`sig-doc0-2`,
/// `signed-props-sig-doc0-2`, and so on) rather than refused. The first
/// signature is not read, not rewritten and not removed; the second one is a
/// sibling of it.
pub(crate) fn allocate_id(
    lookup: &dsig::Lookup<'_>,
    base: &str,
    reference_names: &[&str],
) -> Result<String, SignError> {
    for attempt in 1..=MAX_SHARED_IDENTIFIERS {
        let candidate = if attempt == 1 {
            base.to_owned()
        } else {
            format!("{base}-{attempt}")
        };
        if identifiers(&candidate, reference_names)
            .iter()
            .all(|id| lookup.by_id(id).is_none())
        {
            return Ok(candidate);
        }
    }
    Err(SignError::new(
        SignErrorCode::DocumentAlreadySigned,
        "this dossier already holds every identifier a signature here could be \
         given",
    ))
}

/// Escape an attribute value, the same escaper the unsigned writer uses.
pub(crate) fn attribute(value: &str) -> String {
    crate::render::attribute(value)
}

/// Escape element text, the same escaper the unsigned writer uses.
pub(crate) fn text(value: &str) -> String {
    crate::render::text(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ncname_is_a_name_without_a_colon_and_without_markup() {
        for good in ["obj0", "_x", "a-b.c", "\u{e9}rt", "sig-doc0-2"] {
            assert!(is_ncname(good), "{good} is an NCName");
        }
        for bad in [
            "", "0start", "-start", "a:b", "a b", "a\"b", "a<b", "a&b", "a>b",
        ] {
            assert!(!is_ncname(bad), "{bad} is not an NCName");
        }
    }

    #[test]
    fn an_identifier_that_could_break_out_of_an_attribute_is_refused() {
        for bad in ["obj0\" URI=\"", "a<b", "a&b", "a>b", &"x".repeat(257)] {
            let error = check_id("OBJREF", bad).expect_err("refused");
            assert_eq!(error.code(), SignErrorCode::DocumentNotSignable);
            assert!(!error.message().contains(bad), "the value is never echoed");
        }
        check_id("OBJREF", "obj0").expect("a plain identifier is usable");
    }

    #[test]
    fn a_media_type_outside_the_token_characters_is_refused() {
        check_mime_essence("text/plain").expect("a plain essence is usable");
        check_mime_essence("application/vnd.eszigno3+xml").expect("so is a vendor tree");
        for bad in [
            "text",
            "text/",
            "/plain",
            "text/plain; charset=utf-8",
            "text/<plain>",
            "te\"xt/plain",
        ] {
            let error = check_mime_essence(bad).expect_err("refused");
            assert_eq!(error.code(), SignErrorCode::DocumentNotSignable);
        }
    }

    #[test]
    fn a_namespace_holding_markup_is_refused() {
        check_namespace("https://www.microsec.hu/ds/e-szigno30#").expect("usable");
        for bad in [
            "",
            "urn:x\" onload=\"",
            "urn:<x>",
            "urn:x&y",
            "urn:x'y",
            "urn:x\u{7}",
        ] {
            let error = check_namespace(bad).expect_err("refused");
            assert_eq!(error.code(), SignErrorCode::DocumentNotSignable);
        }
    }

    /// A base identifier already in the dossier is disambiguated, and so is
    /// one whose derived identifiers alone are taken.
    #[test]
    fn an_identifier_already_in_the_dossier_is_disambiguated() {
        let names = ["object", "signed-properties"];
        let working = dsig::Working::parse(
            "<a xmlns=\"urn:x\"><b Id=\"sig-doc0\"/><c Id=\"ref-sig-doc0-2-object\"/></a>",
        )
        .expect("this parses");
        working
            .with_tree(|lookup| {
                // `sig-doc0` is taken, and so is one identifier `sig-doc0-2`
                // would introduce, so the third candidate wins.
                assert_eq!(allocate_id(lookup, "sig-doc0", &names)?, "sig-doc0-3");
                assert_eq!(allocate_id(lookup, "sig-doc1", &names)?, "sig-doc1");
                Ok(())
            })
            .expect("an identifier is available");
    }

    #[test]
    fn every_identifier_a_signature_introduces_is_accounted_for() {
        let used = identifiers("sig-doc0", &["object", "signed-properties"]);
        for expected in [
            "sig-doc0",
            "signed-props-sig-doc0",
            "xades-sig-doc0",
            "sigprof-sig-doc0",
            "profile-sig-doc0",
            "ref-sig-doc0-object",
            "ref-sig-doc0-signed-properties",
        ] {
            assert!(used.iter().any(|id| id == expected), "{expected} is used");
        }
    }

    #[test]
    fn the_escapers_are_the_writer_side_ones() {
        assert_eq!(attribute("a\"b&c"), "a&quot;b&amp;c");
        assert_eq!(text("a<b>c"), "a&lt;b&gt;c");
    }
}
