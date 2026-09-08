//! Resolving `--document` selectors against a dossier's top-level documents.

use openszigno_core::Dossier;

use crate::response::CliError;

/// One document a `--document` selector resolved to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Selected {
    pub(crate) index: usize,
    pub(crate) object_ref: String,
}

/// Resolve the `--document` selectors against one dossier's top-level
/// documents.
///
/// A selector is either `#<index>` in source order or an exact `object_ref`.
/// Prefixes are deliberately not accepted: a selector that identified a
/// document only by a shorter string would silently change meaning when the
/// dossier gains a document. The result is in source order, whatever order
/// the selectors were given in, and a document named twice is listed once.
pub(crate) fn resolve_selection(
    dossier: &Dossier,
    selectors: &[String],
) -> Result<Vec<Selected>, CliError> {
    let mut chosen: Vec<usize> = Vec::new();
    for selector in selectors {
        let index = resolve_selector(dossier, selector)?;
        if !chosen.contains(&index) {
            chosen.push(index);
        }
    }
    chosen.sort_unstable();
    Ok(chosen
        .into_iter()
        .map(|index| Selected {
            index,
            object_ref: dossier.documents[index].object_ref.clone(),
        })
        .collect())
}

/// Resolve one selector to a top-level document index.
fn resolve_selector(dossier: &Dossier, selector: &str) -> Result<usize, CliError> {
    // A `dossier_path` like `2/0` names a document inside an embedded dossier,
    // which this flag deliberately cannot reach. Saying so beats letting it
    // fall through to a bare "no such document".
    if selector.contains('/') {
        return Err(CliError::invalid(
            "document_not_found",
            "a --document selector cannot name a document inside an embedded dossier; extract the embedded dossier first and run extract on the file it produced",
        ));
    }
    if let Some(digits) = selector.strip_prefix('#') {
        let index: usize = digits.parse().map_err(|_| {
            CliError::invalid(
                "document_not_found",
                "a #<index> --document selector must be a decimal document index",
            )
        })?;
        return match dossier.documents.iter().any(|item| item.index == index) {
            true => Ok(index),
            false => Err(CliError::invalid(
                "document_not_found",
                format!("no document has index {index}"),
            )),
        };
    }
    let mut matches = dossier
        .documents
        .iter()
        .filter(|document| document.object_ref == selector);
    let first = matches.next().ok_or_else(|| {
        // The selector is an XML ID from the caller's own dossier, not payload
        // content, so echoing it is safe and makes the error usable.
        CliError::invalid(
            "document_not_found",
            format!("no document has the object_ref {selector}"),
        )
    })?;
    if matches.next().is_some() {
        return Err(CliError::invalid(
            "document_ambiguous",
            format!("more than one document has the object_ref {selector}"),
        ));
    }
    Ok(first.index)
}

#[cfg(test)]
mod tests {
    use super::*;

    use openszigno_core::Limits;

    /// A dossier cannot reach this state through the parser, which refuses a
    /// repeated XML ID, so the guard is exercised on a mutated model. It stays
    /// because "pick one" would be the wrong answer if it ever could.
    #[test]
    fn two_documents_sharing_an_object_ref_are_ambiguous() {
        let mut dossier = openszigno_core::parse(
            std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/two-documents.es3"),
            )
            .expect("the fixture is readable")
            .as_slice(),
            &Limits::default(),
        )
        .expect("the fixture parses");
        let shared = dossier.documents[0].object_ref.clone();
        dossier.documents[1].object_ref = shared.clone();

        let error = resolve_selector(&dossier, &shared).expect_err("the selector is ambiguous");
        assert_eq!(error.code, "document_ambiguous");
        assert_eq!(error.exit, 4);
        // An index selector stays usable: it names exactly one document.
        assert_eq!(resolve_selector(&dossier, "#1").expect("index resolves"), 1);
    }

    /// A selector is matched in full: a prefix of an `object_ref` names
    /// nothing, so a selector cannot change meaning as a dossier grows.
    #[test]
    fn an_object_ref_selector_is_never_a_prefix_match() {
        let dossier = openszigno_core::parse(
            std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/two-documents.es3"),
            )
            .expect("the fixture is readable")
            .as_slice(),
            &Limits::default(),
        )
        .expect("the fixture parses");

        assert_eq!(
            resolve_selector(&dossier, "DocumentObject")
                .expect_err("a prefix matches nothing")
                .code,
            "document_not_found"
        );
        assert_eq!(
            resolve_selection(&dossier, &["#1".to_owned(), "DocumentObjectA".to_owned()])
                .expect("both resolve")
                .iter()
                .map(|item| item.index)
                .collect::<Vec<_>>(),
            [0, 1],
            "the selection is returned in source order"
        );
    }
}
