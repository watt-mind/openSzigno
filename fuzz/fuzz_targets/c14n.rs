//! Fuzz `openszigno_verify::c14n`: parse arbitrary bytes as XML through the
//! same `XmlSource` the verifier uses, then canonicalize the whole document
//! with every implemented `C14nAlgorithm` variant.
//!
//! `RoxmltreeC14n` is the only backend this crate ships (see
//! `crates/openszigno-verify/src/c14n.rs`'s module doc for why a second,
//! borrowed backend was rejected), so "each backend variant" here means each
//! of the four canonicalization algorithms it implements.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openszigno_core::{Limits, XmlSource};
use openszigno_verify::c14n::{C14nAlgorithm, C14nBackend, NodeSet, RoxmltreeC14n};

const ALGORITHMS: [C14nAlgorithm; 4] = [
    C14nAlgorithm::Inclusive { comments: false },
    C14nAlgorithm::Inclusive { comments: true },
    C14nAlgorithm::Exclusive { comments: false },
    C14nAlgorithm::Exclusive { comments: true },
];

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let limits = Limits::default();
    let Ok(source) = XmlSource::decode(data, &limits) else {
        return;
    };
    let Ok(tree) = source.parse_tree(&limits) else {
        return;
    };
    let root = tree.root();
    let backend = RoxmltreeC14n;
    for algorithm in ALGORITHMS {
        let set = NodeSet::document(root);
        let _ = backend.canonicalize(source.text(), &set, algorithm, &[]);
        let excluded_comments = NodeSet::document(root).without_comments();
        let _ = backend.canonicalize(source.text(), &excluded_comments, algorithm, &[]);
    }
});
