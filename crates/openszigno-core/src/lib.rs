//! Structural parsing and bounded payload decoding for Microsec e-Szignó dossiers.
//!
//! This crate does not perform XMLDSig or XAdES verification. A successfully
//! parsed dossier is not necessarily authentic.

mod decode;
mod error;
mod model;
mod parse;

pub use decode::{DecodeOutcome, DecodedDocument, UnsupportedReason};
pub use error::{Error, ErrorCode};
pub use model::{Document, Dossier, Limits, MimeType};

pub const ESZIGNO_NAMESPACE: &str = "https://www.microsec.hu/ds/e-szigno30#";
pub const XMLDSIG_NAMESPACE: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Parse a bounded e-dossier from memory.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Dossier, Error> {
    parse::parse(bytes, limits)
}
