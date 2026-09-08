//! Synthetic test material: a small PKI, an XMLDSig/XAdES signer, revocation
//! and timestamp builders, and a synthetic trusted list.
//!
//! Signing lives here and nowhere else. Creating or signing a dossier is a
//! permanent non-goal of the shipped tool; this helper exists only so that the
//! verifier can be tested against material it did not itself produce the
//! verification logic for, and it must never move into a shipped crate.
//!
//! Every byte here is generated. Nothing is derived from a real dossier.
//!
//! The module is split by concern, each file kept well under the repository's
//! 800-line source-file guideline (see `scripts/check-file-length.py`):
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`keys`] | Committed synthetic RSA private keys. |
//! | [`pki`] | Synthetic keys (RSA, ECDSA, Ed25519), certificates, and certificate extension builders. |
//! | [`dossier`] | XML namespace/algorithm constants, the specs describing a synthetic dossier, and its unsigned rendering. |
//! | [`signer`] | XMLDSig/XAdES signing of a synthetic dossier built from [`dossier`]'s specs. |
//! | [`timestamps`] | RFC 3161 timestamp tokens from a synthetic TSA. |
//! | [`cms`] | Synthetic CRLs and OCSP responses. |
//! | [`trustlist`] | A synthetic ETSI TS 119 612 trusted list. |
//! | [`harness`] | The end-to-end verification harness the `verify*` suites share. |
//!
//! Every item is re-exported here, so existing `use common::{...}` imports in
//! the test suites keep compiling unchanged regardless of which file an item
//! lives in.

#![allow(dead_code)]
// Every test binary includes this module afresh through `mod common;` (or by
// path from another crate), but pulls in only the items it uses through
// `use common::{...}`. A blanket re-export is what keeps every existing
// `use` path compiling unchanged across the split described above, so an
// individual binary not touching one whole concern (say, `trustlist`) is
// expected and not a sign of dead code.
#![allow(unused_imports)]

pub mod cms;
pub mod dossier;
pub mod harness;
pub mod keys;
pub mod pki;
pub mod signer;
pub mod timestamps;
pub mod trustlist;

pub use cms::*;
pub use dossier::*;
pub use harness::*;
pub use pki::*;
pub use signer::*;
pub use timestamps::*;
pub use trustlist::*;
