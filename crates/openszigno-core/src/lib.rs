//! Structural parsing and bounded payload decoding for Microsec e-Szignó dossiers.
//!
//! This crate does not perform XMLDSig or XAdES verification. A successfully
//! parsed dossier is not necessarily authentic.

mod decode;
mod decrypt;
mod error;
mod inventory;
mod model;
mod parse;
mod scan;
mod sniff;
mod text;
mod xml;

pub use decode::{DecodeOutcome, DecodedDocument, UnsupportedReason, decode_document_with};
pub use decrypt::{DecryptOptions, RecipientKey};
pub use error::{Error, ErrorCode};
pub use model::{
    Document, Dossier, Limits, MAX_INVENTORIED_DIGEST_METHODS, MAX_INVENTORIED_REFERENCE_URIS,
    MAX_INVENTORIED_SIGNATURES, MAX_INVENTORIED_TIMESTAMPS, MAX_INVENTORIED_XADES_PROPERTIES,
    MimeType, ParseOptions, SignatureEvidence, SignaturePlacement, SignatureSummary,
    StructuralWarning, StructuralWarningCode, TimestampPlacement, TimestampSummary,
};
pub use sniff::{DetectedType, sniff};
pub use text::{MAX_DISPLAY_CHARS, sanitize_display};
pub use xml::{EncodingDeclaration, XmlSource, declared_encoding, id_map};

/// The XML parser this crate builds every tree with. Re-exported so that a
/// verifier operates on exactly the same tree the structural parser saw.
pub use roxmltree;

pub const ESZIGNO_NAMESPACE: &str = "https://www.microsec.hu/ds/e-szigno30#";
pub const XMLDSIG_NAMESPACE: &str = "http://www.w3.org/2000/09/xmldsig#";

/// The XAdES namespaces the signature inventory recognises: 1.1.1, 1.2.2,
/// 1.3.2, and 1.4.1. A qualifying-properties element in any other namespace is
/// not described, because its element names would not mean what they say.
pub const XADES_NAMESPACES: &[&str] = &[
    "http://uri.etsi.org/01903/v1.1.1#",
    "http://uri.etsi.org/01903/v1.2.2#",
    "http://uri.etsi.org/01903/v1.3.2#",
    "http://uri.etsi.org/01903/v1.4.1#",
];

/// Namespaces whose `Dossier` root element this crate accepts by default.
///
/// The specification allows a dossier profile to use its own namespace as long
/// as it stays compliant with the default schema. These are the default
/// Microsec namespace and the four Hungarian company-court (e-cégeljárás)
/// generations seen in practice. Anything else is a `wrong_root` error unless
/// the caller adds it to [`ParseOptions::allowed_namespaces`].
pub const KNOWN_COMPATIBLE_NAMESPACES: &[&str] = &[
    ESZIGNO_NAMESPACE,
    "http://www.e-cegjegyzek.hu/2007/e-cegeljaras#",
    "http://www.e-cegjegyzek.hu/2009/e-cegeljaras#",
    "http://www.e-cegjegyzek.hu/2012/e-cegeljaras#",
    "http://www.e-cegjegyzek.hu/2014/e-cegeljaras#",
];

/// Parse a bounded e-dossier from memory, accepting the known-compatible
/// namespaces only.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Dossier, Error> {
    parse_with_options(bytes, &ParseOptions::with_limits(limits.clone()))
}

/// Parse a bounded e-dossier from memory with an explicit namespace policy.
pub fn parse_with_options(bytes: &[u8], options: &ParseOptions) -> Result<Dossier, Error> {
    parse::parse(bytes, options)
}
