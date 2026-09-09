//! Fuzz extraction planning: turning arbitrary document titles, declared
//! extensions and document indices into output filenames, and deduplicating
//! those names inside one directory.
//!
//! The planner lives in the `openszigno` binary crate, which has no library
//! target to depend on, so its two modules are included here by path, over a
//! small stand-in for the `response` module they name their errors through.
//! What is fuzzed is therefore the shipped `extract/names.rs` and
//! `extract/plan.rs`, not a copy of them.
//!
//! The titles reach the planner the way a real one does — through a synthetic
//! dossier this target builds and `openszigno_core::parse` reads — so a title
//! the parser itself refuses never reaches the naming rules, exactly as in the
//! shipped tool.
//!
//! What is asserted, beyond "no panic":
//!
//! - **No planned name is a path.** A name carrying `/`, `\`, a NUL, or that
//!   is `.` or `..` would let an extraction write outside the directory it was
//!   given. This is the extraction-safety invariant of
//!   `docs/architecture.md`, stated where a fuzzer can hit it.
//! - **No two planned names collide.** Every name in one directory is distinct
//!   under the planner's own comparison key, which is what keeps two documents
//!   from being written to one file on a case-insensitive filesystem.
//! - **Naming is idempotent.** Planning the same dossier twice yields exactly
//!   the same names, in the same order: a deduplicated name is derived from
//!   the document's index and its position, never from anything that moves
//!   between runs.

#![no_main]

use arbitrary::{Arbitrary as _, Unstructured};
use libfuzzer_sys::fuzz_target;
use openszigno_core::{DecryptOptions, ParseOptions, parse_with_options};

/// The `crate::response` items `names.rs` and `plan.rs` name their outcomes
/// through. Only the shapes they use are reproduced; nothing here is under
/// test, and the exit statuses are the shipped ones so a copy that drifted is
/// obvious.
#[allow(dead_code)]
mod response {
    #[derive(Clone, Debug)]
    pub(crate) struct Notice {
        pub(crate) code: String,
        pub(crate) message: String,
    }

    #[derive(Debug)]
    pub(crate) struct CliError {
        pub(crate) code: &'static str,
        pub(crate) message: String,
        pub(crate) exit: u8,
    }

    impl CliError {
        pub(crate) fn extraction(error: openszigno_core::Error) -> Self {
            Self {
                code: error.code().as_str(),
                message: error.message().to_owned(),
                exit: 5,
            }
        }

        pub(crate) fn unsafe_output(code: &'static str, message: impl Into<String>) -> Self {
            Self {
                code,
                message: message.into(),
                exit: 5,
            }
        }
    }
}

// The two modules are declared at the top level, because a `#[path]` inside
// an inline module is resolved against a directory named after that module,
// which does not exist here. `extract` then re-exports them under the names
// `plan.rs` uses to reach `names.rs` (`crate::extract::names`), so the
// included source needs no edit at all.
#[allow(dead_code)]
#[path = "../../crates/openszigno-cli/src/extract/names.rs"]
mod names_source;
#[allow(dead_code)]
#[path = "../../crates/openszigno-cli/src/extract/plan.rs"]
mod plan_source;

mod extract {
    pub(crate) use super::{names_source as names, plan_source as plan};
}

use extract::names::name_key;
use extract::plan::{Plan, PlanDir};

/// One document the fuzzer asked for.
struct Wanted {
    title: String,
    extension: Option<String>,
}

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            // A C0 control other than tab, LF and CR is not legal XML 1.0
            // content, and the parser refuses it before the naming rules ever
            // see it; dropping it keeps the input about naming.
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {}
            c => out.push(c),
        }
    }
    out
}

fn dossier_xml(documents: &[Wanted]) -> String {
    let mut body = String::new();
    for (index, wanted) in documents.iter().enumerate() {
        let extension = wanted.extension.as_ref().map_or_else(String::new, |value| {
            format!(" extension=\"{}\"", xml_escape(value))
        });
        body.push_str(&format!(
            "<es:Document><es:DocumentProfile Id=\"p{index}\" OBJREF=\"o{index}\">\
             <es:Title>{title}</es:Title>\
             <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>\
             <es:Format><es:MIME-Type type=\"text\" subtype=\"plain\"{extension}/></es:Format>\
             <es:SourceSize sizeValue=\"1\" sizeUnit=\"B\"/>\
             <es:BaseTransform><es:Transform Algorithm=\"base64\"/></es:BaseTransform>\
             </es:DocumentProfile><ds:Object Id=\"o{index}\">eA==</ds:Object></es:Document>",
            title = xml_escape(&wanted.title),
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<es:Dossier xmlns:es=\"https://www.microsec.hu/ds/e-szigno30#\" \
xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
<es:DossierProfile Id=\"DossierProfile1\" OBJREF=\"Object0\">\
<es:Title>fuzz</es:Title>\
<es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate></es:DossierProfile>\
<es:Documents Id=\"Object0\">{body}</es:Documents></es:Dossier>"
    )
}

/// Check one planned directory, and every directory under it, then collect
/// every planned name in plan order so two runs can be compared.
///
/// Uniqueness is asserted per directory, which is the scope the planner
/// deduplicates in: the same name in two different subdirectories is no
/// collision, and must not be reported as one.
fn check(plan: &PlanDir, into: &mut Vec<String>) {
    let mut claimed: Vec<String> = Vec::new();
    let mut claim = |name: &str| {
        assert!(!name.is_empty(), "a planned name is never empty");
        assert!(
            !name.contains('/') && !name.contains('\\') && !name.contains('\0'),
            "a planned name must not be a path: {name:?}"
        );
        assert!(
            name != "." && name != "..",
            "a planned name must not be a directory reference: {name:?}"
        );
        assert!(
            name.len() <= 255,
            "a planned name is bounded to 255 bytes: {name:?}"
        );
        let key = name_key(name);
        assert!(
            !claimed.contains(&key),
            "two planned names collide in one directory: {name:?}"
        );
        claimed.push(key);
    };
    for entry in &plan.entries {
        claim(&entry.file.name);
        if let Some(subdirectory) = &entry.subdirectory {
            claim(&subdirectory.name);
        }
    }
    for entry in &plan.entries {
        into.push(entry.file.name.clone());
        if let Some(subdirectory) = &entry.subdirectory {
            into.push(subdirectory.name.clone());
            check(subdirectory, into);
        }
    }
}

fn plan_once(dossier: &openszigno_core::Dossier, options: &ParseOptions) -> Option<PlanDir> {
    let mut plan = Plan {
        options,
        decrypt: DecryptOptions::default(),
        recursive: true,
        max_depth: 2,
        selection: None,
        total: 0,
        warnings: Vec::new(),
        skipped: 0,
        nested_dossiers: 0,
    };
    plan.plan_dossier(dossier, String::new(), "", String::new(), 0)
        .ok()
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    let mut unstructured = Unstructured::new(data);
    let mut documents = Vec::new();
    // At most eight documents: the planner's behaviour is about collisions
    // between a handful of titles, and a longer list only slows the run down.
    while documents.len() < 8 && !unstructured.is_empty() {
        let Ok(title) = String::arbitrary(&mut unstructured) else {
            break;
        };
        let extension = Option::<String>::arbitrary(&mut unstructured).unwrap_or(None);
        documents.push(Wanted { title, extension });
    }
    if documents.is_empty() {
        return;
    }

    let options = ParseOptions::default();
    let xml = dossier_xml(&documents);
    let Ok(dossier) = parse_with_options(xml.as_bytes(), &options) else {
        return;
    };

    let Some(planned) = plan_once(&dossier, &options) else {
        return;
    };
    let mut names = Vec::new();
    check(&planned, &mut names);

    // The same dossier plans to the same names: nothing in the naming rules
    // depends on anything that moves between runs.
    let again = plan_once(&dossier, &options).expect("a plan that succeeded once succeeds again");
    let mut repeated = Vec::new();
    check(&again, &mut repeated);
    assert_eq!(names, repeated, "planning is not idempotent");
});
