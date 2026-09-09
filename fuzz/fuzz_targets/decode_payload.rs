//! Fuzz the document decode chains (`openszigno_core::decode`) through a
//! synthetic minimal dossier that wraps the fuzzed bytes as one document's
//! payload: `base64`, `zip -> base64`, and the two `encrypt` chains without a
//! decryption key.
//!
//! The `encrypt` chains are here as well as in `decrypt_cms` because they are
//! a different path: with no `--decrypt-key` the transform is never reversed,
//! and what is exercised is the chain walker deciding that — recognising the
//! transform, refusing to treat the payload as content, and reporting
//! `Unsupported` rather than handing back ciphertext as if it were a
//! document. `decrypt_cms` covers the other half, where a key is supplied and
//! the CMS is actually parsed.
//!
//! `decode_document` is not itself public on an arbitrary `Document` (its
//! `payload` field is crate-private, by design: a `Document` only ever comes
//! from a dossier this crate parsed), so the harness goes through the public
//! surface a real caller uses: parse a tiny synthetic `.es3` wrapper whose
//! `ds:Object` text is the fuzzed bytes, then decode document 0.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openszigno_core::{DecodeOutcome, DecryptOptions, Limits, decode_document_with, parse};

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            // A lone NUL or other control character (besides tab/LF/CR) is
            // not legal XML 1.0 content; drop it rather than let it make the
            // dossier fail to parse for a reason unrelated to what this
            // target exercises.
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {}
            c => out.push(c),
        }
    }
    out
}

fn dossier_xml(payload: &str, transforms: &[&str]) -> String {
    let transform_elements: String = transforms
        .iter()
        .map(|algorithm| format!(r#"<es:Transform Algorithm="{algorithm}"/>"#))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:DossierProfile Id="DossierProfile1" OBJREF="Object0">
    <es:Title>fuzz</es:Title>
    <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>
  </es:DossierProfile>
  <es:Documents Id="Object0">
    <es:Document>
      <es:DocumentProfile Id="DocumentProfile1" OBJREF="DocumentObject1">
        <es:Title>fuzz.bin</es:Title>
        <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="application" subtype="octet-stream"/></es:Format>
        <es:BaseTransform>{transform_elements}</es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="DocumentObject1">{payload}</ds:Object>
    </es:Document>
  </es:Documents>
</es:Dossier>"#
    )
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 256 * 1024 {
        return;
    }
    let (selector, rest) = data.split_at(1);
    let transforms: &[&str] = match selector[0] % 4 {
        0 => &["base64"],
        1 => &["zip", "base64"],
        2 => &["encrypt", "base64"],
        // A chain the writer never produces, so that the walker's handling of
        // an unexpected order is exercised too.
        _ => &["encrypt", "zip", "base64"],
    };
    let payload = xml_escape(&String::from_utf8_lossy(rest));
    let xml = dossier_xml(&payload, transforms);

    let limits = Limits::default();
    let Ok(dossier) = parse(xml.as_bytes(), &limits) else {
        return;
    };
    if dossier.documents.is_empty() {
        return;
    }
    // `decode_document` is `decode_document_with` under
    // `DecryptOptions::default()`; both are driven so the convenience wrapper
    // and the explicit form stay in step, and so the `encrypt` chains above go
    // through the entry point that takes a decryption policy.
    let _ = dossier.decode_document(0, &limits);
    let no_key = DecryptOptions::default();
    let outcome = decode_document_with(&dossier, 0, &limits, &no_key);
    if let Ok(DecodeOutcome::Decoded(decoded)) = &outcome {
        // Without a key nothing is ever decrypted, whatever the chain said.
        assert!(
            !decoded.decrypted,
            "a decode with no key must never report a decryption"
        );
    }
});
