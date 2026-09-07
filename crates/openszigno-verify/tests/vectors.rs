//! Independent verification vectors.
//!
//! Every other suite in this crate signs its fixtures with the in-tests
//! helper, which canonicalizes through the very backend under test. A mistake
//! shared by the signer and the verifier cancels out there and the tests still
//! pass. Nothing in this file was produced by openSzigno:
//!
//! - the canonical forms below are transcribed from the W3C Recommendations
//!   (Canonical XML 1.0 section 3, Exclusive XML Canonicalization 1.0 section
//!   2.2), with the section cited at each one;
//! - `tests/fixtures/xmldsig/` holds a complete signed dossier whose reference
//!   digests and `ds:SignatureValue` were computed by OpenSSL and Python over
//!   canonical octets written out by hand from those same rules. See that
//!   directory's `README.md` for the generator and the exact commands.
//!
//! If the canonicalizer drifts, these stop matching. That is the point.

use std::path::{Path, PathBuf};

use openszigno_core::{Limits, XmlSource};
use openszigno_verify::c14n::{C14nAlgorithm, C14nBackend, NodeSet, RoxmltreeC14n};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{
    FixedClock, MemoryTrustStore, NoRevocation, RoxmltreeC14n as Backend, Verdict, VerifyOptions,
    VerifyReport, parse_rfc3339, verify,
};

// ---------------------------------------------------------------------------
// Canonical forms transcribed from the specifications
// ---------------------------------------------------------------------------

/// Canonicalize the whole document, or the subtree rooted at the first element
/// with the given local name.
///
/// Selecting by name rather than by an added `Id` keeps each transcribed vector
/// exactly as the specification prints it: an extra unprefixed attribute would
/// change the expected attribute order, since C14N sorts unnamespaced
/// attributes before namespaced ones.
fn canonicalize(xml: &str, algorithm: C14nAlgorithm, element: Option<&str>) -> String {
    let source = XmlSource::decode(xml.as_bytes(), &Limits::default()).expect("the input decodes");
    let tree = source
        .parse_tree(&Limits::default())
        .expect("the input parses");
    let set = match element {
        None => NodeSet::document(tree.root()),
        Some(name) => NodeSet::subtree(
            tree.descendants()
                .find(|node| node.is_element() && node.tag_name().name() == name)
                .expect("the named element exists"),
        ),
    };
    String::from_utf8(
        RoxmltreeC14n
            .canonicalize(source.text(), &set, algorithm, &[])
            .expect("the input canonicalizes"),
    )
    .expect("canonical XML is UTF-8")
}

const INCLUSIVE: C14nAlgorithm = C14nAlgorithm::Inclusive { comments: false };
const EXCLUSIVE: C14nAlgorithm = C14nAlgorithm::Exclusive { comments: false };

/// Canonical XML 1.0, section 3.2 "Whitespace in Document Content". The
/// canonical form is byte-identical to the input: every space between tags and
/// inside character content is retained, clean or dirty.
#[test]
fn c14n_specification_section_3_2_whitespace() {
    let input = "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>";
    assert_eq!(canonicalize(input, INCLUSIVE, None), input);
}

/// Canonical XML 1.0, section 3.4 "Character Modifications and Character
/// References", reduced to the cases that do not need a DTD: this parser
/// refuses a `DOCTYPE` outright, so the `normId`, `normNames` and `norm`
/// elements — whose expected output depends on declared attribute types — are
/// left out, and the rest is transcribed unchanged.
///
/// What it pins: character references are replaced by their characters, a
/// literal carriage return in text is written back as `&#xD;`, CDATA sections
/// are replaced by their content with `<`, `>` and `&` escaped, and in
/// attribute values `"`, `<`, `&` and the whitespace characters become
/// character references while `>` does not.
#[test]
fn c14n_specification_section_3_4_character_modifications() {
    let input = concat!(
        "<doc>\n",
        "   <text>First line&#x0d;&#10;Second line</text>\n",
        "   <value>&#x32;</value>\n",
        "   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n",
        "   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n",
        "</doc>"
    );
    let expected = concat!(
        "<doc>\n",
        "   <text>First line&#xD;\nSecond line</text>\n",
        "   <value>2</value>\n",
        "   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n",
        "   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n",
        "</doc>"
    );
    assert_eq!(canonicalize(input, INCLUSIVE, None), expected);
}

/// Canonical XML 1.0, section 3.6 "UTF-8 Encoding": the canonical form is
/// UTF-8 whatever the input encoding was, and a character reference is
/// replaced by the character it names.
///
/// The specification's own listing is an ISO-8859-1 document. This parser
/// accepts only UTF-8 and ISO-8859-2 — the encodings e-dossiers actually use —
/// so the transcoding half is transcribed in ISO-8859-2 instead: octet 0xF5 in
/// that character set is U+0151, "latin small letter o with double acute",
/// whose UTF-8 form is C5 91. The rule under test is the specification's.
#[test]
fn c14n_specification_section_3_6_utf8_encoding() {
    // A character reference, replaced by its character and emitted as UTF-8.
    let input = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<doc>&#169;</doc>";
    assert_eq!(
        canonicalize(input, INCLUSIVE, None).as_bytes(),
        b"<doc>\xc2\xa9</doc>"
    );

    // The same character written as an octet in a non-UTF-8 encoding, and the
    // same canonical output.
    let input = "<?xml version=\"1.0\" encoding=\"ISO-8859-2\"?>\n<doc>&#169;</doc>";
    assert_eq!(
        canonicalize(input, INCLUSIVE, None).as_bytes(),
        b"<doc>\xc2\xa9</doc>"
    );

    // Transcoding proper: one ISO-8859-2 octet becomes the two UTF-8 octets of
    // the character it denotes.
    let mut latin2: Vec<u8> = "<?xml version=\"1.0\" encoding=\"ISO-8859-2\"?>\n<doc>"
        .as_bytes()
        .to_vec();
    latin2.push(0xf5);
    latin2.extend_from_slice(b"</doc>");
    let source = XmlSource::decode(&latin2, &Limits::default()).expect("the input decodes");
    let tree = source
        .parse_tree(&Limits::default())
        .expect("the input parses");
    let octets = RoxmltreeC14n
        .canonicalize(
            source.text(),
            &NodeSet::document(tree.root()),
            INCLUSIVE,
            &[],
        )
        .expect("the input canonicalizes");
    assert_eq!(octets, b"<doc>\xc5\x91</doc>");
}

/// Exclusive XML Canonicalization 1.0, section 2.2 "General Problems with
/// re-Enveloping". The same `n1:elem2` subtree in two different envelopes:
/// inclusive canonicalization drags the surrounding context in and the two
/// results differ, while exclusive canonicalization yields the same octets for
/// both. The spec re-indents its listings to fit the page; the indentation
/// here is the input's own, and what is transcribed is the part the
/// specification is about — which namespace declarations and `xml:*`
/// attributes are rendered, and in what order.
#[test]
fn exclusive_c14n_specification_section_2_2_re_enveloping() {
    let first = concat!(
        "<n0:local xmlns:n0=\"foo:bar\" xmlns:n3=\"ftp://example.org\">",
        "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">",
        "<n3:stuff xmlns:n3=\"ftp://example.org\"/>",
        "</n1:elem2></n0:local>"
    );
    let second = concat!(
        "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\"",
        " xml:lang=\"fr\" xml:space=\"retain\">",
        "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">",
        "<n3:stuff xmlns:n3=\"ftp://example.org\"/>",
        "</n1:elem2></n2:pdu>"
    );

    // Inclusive: the context leaks in, and it leaks in differently.
    assert_eq!(
        canonicalize(first, INCLUSIVE, Some("elem2")),
        concat!(
            "<n1:elem2 xmlns:n0=\"foo:bar\" xmlns:n1=\"http://example.net\"",
            " xmlns:n3=\"ftp://example.org\" xml:lang=\"en\">",
            "<n3:stuff></n3:stuff>",
            "</n1:elem2>"
        )
    );
    assert_eq!(
        canonicalize(second, INCLUSIVE, Some("elem2")),
        concat!(
            "<n1:elem2 xmlns:n1=\"http://example.net\" xmlns:n2=\"http://foo.example\"",
            " xml:lang=\"en\" xml:space=\"retain\">",
            "<n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>",
            "</n1:elem2>"
        )
    );

    // Exclusive: the same octets in both envelopes, which is the property a
    // signature over a subtree depends on.
    let expected = concat!(
        "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">",
        "<n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>",
        "</n1:elem2>"
    );
    assert_eq!(canonicalize(first, EXCLUSIVE, Some("elem2")), expected);
    assert_eq!(canonicalize(second, EXCLUSIVE, Some("elem2")), expected);
}

// ---------------------------------------------------------------------------
// A signed document produced outside this project
// ---------------------------------------------------------------------------

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/xmldsig")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).expect("the fixture is readable")
}

fn run_vector(anchors: Vec<Vec<u8>>) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = NoRevocation;
    let backend = Backend;
    // Inside the committed certificates' validity window, so the vector does
    // not depend on the wall clock.
    let clock = FixedClock(parse_rfc3339("2027-01-01T00:00:00Z").expect("parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some("2027-01-01T00:00:00Z".to_owned());
    verify(&read("openssl-rsa-sha256.es3"), &options).expect("the vector parses structurally")
}

fn anchor() -> Vec<Vec<u8>> {
    openszigno_verify::certs::certificates_from_bytes(&read("root.pem"))
        .expect("the anchor is a certificate")
}

/// The canonical `ds:SignedInfo` octets OpenSSL signed are committed beside the
/// document. This crate's canonicalizer must produce them byte for byte;
/// everything else in this file rests on that.
#[test]
fn the_canonical_signed_info_matches_the_committed_octets() {
    let document = read("openssl-rsa-sha256.es3");
    let expected = read("signedinfo.canonical");
    let source = XmlSource::decode(&document, &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let signed_info = tree
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "SignedInfo")
        .expect("the vector has a ds:SignedInfo");
    let octets = RoxmltreeC14n
        .canonicalize(
            source.text(),
            &NodeSet::subtree(signed_info),
            EXCLUSIVE,
            &[],
        )
        .expect("canonicalizes");
    assert_eq!(
        String::from_utf8(octets).expect("UTF-8"),
        String::from_utf8(expected).expect("UTF-8")
    );
}

/// The whole pipeline over material this project did not produce: the three
/// reference digests were computed by Python's hashlib and the signature by
/// OpenSSL, over octets written out by hand from the canonicalization rules.
#[test]
fn the_openssl_vector_verifies_end_to_end() {
    let report = run_vector(anchor());
    let seen: Vec<String> = report.signatures[0]
        .checks
        .iter()
        .map(|check| format!("{}={}", check.code.as_str(), check.status.as_str()))
        .collect();
    for code in [
        CheckCode::ReferenceDigestOk,
        CheckCode::SignedInfoCanonicalization,
        CheckCode::SignatureValueOk,
        CheckCode::ReferenceScopeComplete,
        CheckCode::CertPathOk,
    ] {
        assert!(
            seen.contains(&format!("{}=passed", code.as_str())),
            "expected {} to pass over the OpenSSL vector; got {seen:?}",
            code.as_str()
        );
    }
    assert_eq!(report.counts.signatures, 1);
    assert_eq!(report.signatures[0].references.len(), 3);
    assert!(
        report.signatures[0]
            .references
            .iter()
            .all(|reference| reference.status == CheckStatus::Passed)
    );
    // Still not `valid`: revocation is unchecked, whoever produced the file.
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// One flipped byte in the payload breaks the digest OpenSSL's signature is
/// computed over, which is the negative half of the vector.
#[test]
fn a_tampered_vector_fails() {
    let document = String::from_utf8(read("openssl-rsa-sha256.es3")).expect("UTF-8");
    let tampered = document.replace(
        "<ds:Object xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"obj0\">aGVsbG8=",
        "<ds:Object xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"obj0\">aGVsbG9=",
    );
    assert_ne!(tampered, document, "the payload must actually change");

    let trust = MemoryTrustStore::new(anchor(), Vec::new());
    let revocation = NoRevocation;
    let backend = Backend;
    let clock = FixedClock(parse_rfc3339("2027-01-01T00:00:00Z").expect("parses"));
    let options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    let report = verify(tampered.as_bytes(), &options).expect("parses structurally");

    let seen: Vec<String> = report.signatures[0]
        .checks
        .iter()
        .map(|check| format!("{}={}", check.code.as_str(), check.status.as_str()))
        .collect();
    assert!(
        seen.contains(&"reference_digest_mismatch=failed".to_owned()),
        "expected the digest to fail; got {seen:?}"
    );
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// Without the generated root in the store the same signature still verifies
/// cryptographically, and the chain is simply unknown: a vector must not be
/// able to smuggle in its own trust.
#[test]
fn the_vector_supplies_no_trust_of_its_own() {
    let report = run_vector(Vec::new());
    let seen: Vec<String> = report.signatures[0]
        .checks
        .iter()
        .map(|check| format!("{}={}", check.code.as_str(), check.status.as_str()))
        .collect();
    assert!(seen.contains(&"signature_value_ok=passed".to_owned()));
    assert!(seen.contains(&"cert_path_unknown=unknown".to_owned()));
    assert_eq!(report.verdict, Verdict::Indeterminate);
}
