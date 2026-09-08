//! Fuzz the Base64 and `zip -> base64` document decode chains
//! (`openszigno_core::decode`) through a synthetic minimal dossier that
//! wraps the fuzzed bytes as one document's payload.
//!
//! `decode_document` is not itself public on an arbitrary `Document` (its
//! `payload` field is crate-private, by design: a `Document` only ever comes
//! from a dossier this crate parsed), so the harness goes through the public
//! surface a real caller uses: parse a tiny synthetic `.es3` wrapper whose
//! `ds:Object` text is the fuzzed bytes, then decode document 0.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openszigno_core::{Limits, parse};

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
    let transforms: &[&str] = if selector[0] % 2 == 0 {
        &["base64"]
    } else {
        &["zip", "base64"]
    };
    let payload = xml_escape(&String::from_utf8_lossy(rest));
    let xml = dossier_xml(&payload, transforms);

    let limits = Limits::default();
    if let Ok(dossier) = parse(xml.as_bytes(), &limits)
        && !dossier.documents.is_empty()
    {
        let _ = dossier.decode_document(0, &limits);
    }
});
