//! What a hostile dossier is allowed to put on a terminal, and in the JSON
//! envelope.
//!
//! `SECURITY.md` promises that a hostile input cannot put terminal control
//! sequences or bidirectional overrides into human output, an error message,
//! or the JSON envelope. The bounded XML parser already refuses the C0 and C1
//! control ranges, so `ESC` cannot arrive through a dossier at all; what these
//! tests hold is the rest of it — the Unicode `Cf` class, where the
//! bidirectional overrides live, and length, since nothing in the e-dossier
//! format bounds a `subtype` or a title.
//!
//! Every input here is generated in the test. Nothing is committed: a fixture
//! carrying an invisible character is a fixture nobody can read in review.

#[path = "../../openszigno-verify/tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{
    CertSpec, DossierSpec, SigSpec, document_signature, issued_by, keys, rsa_key, self_signed,
};
use rcgen::BasicConstraints;
use serde_json::Value;

/// The right-to-left override: the character that makes `OK<RLO>txt.exe`
/// display as `OKexe.txt` and a payload look like the thing it is not.
const RLO: char = '\u{202e}';

/// Every `Cf` character these tests plant, so an assertion catches a filter
/// that dropped only the famous one.
const HIDDEN: [char; 4] = ['\u{202e}', '\u{200f}', '\u{2066}', '\u{feff}'];

/// The cap the CLI holds an ordinary dossier-derived value to, and the wider
/// one it holds a title to. Kept here as literals rather than imported: these
/// are the contract this test is about, and a test that reads the constant it
/// is checking checks nothing.
const MAX_DISPLAY_CHARS: usize = 128;
const MAX_TITLE_CHARS: usize = 256;

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("the test binary has a path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("openszigno")
}

fn run(arguments: &[&str]) -> Output {
    Command::new(binary())
        .args(arguments)
        .output()
        .expect("the binary runs")
}

/// A scratch directory under a fully resolved base path: the extractor
/// refuses an output path containing a symlink, and the platform temporary
/// directory is one on some systems.
fn scratch() -> tempfile::TempDir {
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory resolves");
    tempfile::Builder::new()
        .prefix("openszigno-hostile-")
        .tempdir_in(base)
        .expect("a scratch directory is created")
}

fn write(directory: &Path, name: &str, xml: &str) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, xml).expect("the dossier is written");
    path
}

/// A dossier whose every caller-visible string is hostile: a title that reads
/// as a `.txt` and is not one, a 400-character `subtype` that nothing in the
/// format bounds, an object reference and a transform name with overrides in
/// them, and a document title that is safe to write to disk so that `extract`
/// gets far enough to report on it.
fn hostile_dossier() -> String {
    let subtype = "x".repeat(400);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:DossierProfile Id="DossierProfile1" OBJREF="Object0">
    <es:Title>OK{RLO}txt.exe</es:Title>
    <es:E-category>electronic{feff} dossier</es:E-category>
    <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>
  </es:DossierProfile>
  <es:Documents Id="Object0">
    <es:Document>
      <es:DocumentProfile Id="DocumentProfile1" OBJREF="Doc{rlm}Object1">
        <es:Title>hello.txt</es:Title>
        <es:E-category>electronic data</es:E-category>
        <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="te{lri}xt" subtype="{subtype}" extension="txt" charSet="UTF-8"/></es:Format>
        <es:SourceSize sizeValue="41" sizeUnit="B"/>
        <es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="Doc{rlm}Object1">SGVsbG8gZnJvbSBvcGVuU3ppZ25vIHN5bnRoZXRpYyBmaXh0dXJlLgo=</ds:Object>
    </es:Document>
  </es:Documents>
</es:Dossier>
"#,
        RLO = RLO,
        feff = '\u{feff}',
        rlm = '\u{200f}',
        lri = '\u{2066}',
    )
}

/// Assert that nothing a terminal acts on, and nothing unbounded, survived.
fn assert_clean(what: &str, output: &Output) {
    for stream in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        let text = String::from_utf8((stream.1).clone())
            .unwrap_or_else(|_| panic!("{what} {} is UTF-8", stream.0));
        for hidden in HIDDEN {
            assert!(
                !text.contains(hidden),
                "{what} {} carries U+{:04X}",
                stream.0,
                hidden as u32
            );
        }
        assert!(
            !text.contains('\u{1b}'),
            "{what} {} carries an escape",
            stream.0
        );
    }
}

/// Walk a JSON value and assert every string is stripped and bounded.
fn assert_bounded(what: &str, value: &Value, key: Option<&str>) {
    match value {
        Value::String(text) => {
            for hidden in HIDDEN {
                assert!(
                    !text.contains(hidden),
                    "{what}: the {} field carries U+{:04X}",
                    key.unwrap_or("(root)"),
                    hidden as u32
                );
            }
            // `path` is an extracted file's name on disk, which the extraction
            // name rules already stripped and bounded; the envelope has to
            // keep naming the file that was actually written.
            let limit = match key {
                Some("path") => usize::MAX,
                Some("title") => MAX_TITLE_CHARS,
                Some("message" | "reason") => 512,
                _ => MAX_DISPLAY_CHARS,
            };
            assert!(
                text.chars().count() <= limit,
                "{what}: the {} field is {} characters, over its {limit}",
                key.unwrap_or("(root)"),
                text.chars().count()
            );
        }
        Value::Array(items) => {
            for item in items {
                assert_bounded(what, item, key);
            }
        }
        Value::Object(fields) => {
            for (name, item) in fields {
                assert_bounded(what, item, Some(name.as_str()));
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// The reading commands
// ---------------------------------------------------------------------------

/// A title carrying a right-to-left override and a 400-character `subtype`
/// reach neither the human summary nor the JSON envelope, on any of the four
/// commands that read a dossier without verifying it.
#[test]
fn a_hostile_title_and_an_unbounded_subtype_reach_neither_channel() {
    let directory = scratch();
    let path = write(directory.path(), "hostile.es3", &hostile_dossier());
    let file = path.to_str().expect("the path is UTF-8");

    for command in ["inspect", "list", "validate-structure"] {
        let human = run(&[command, file]);
        assert!(human.status.success(), "{command} succeeds");
        assert_clean(&format!("{command} (human)"), &human);

        let json = run(&[command, file, "--json"]);
        assert!(json.status.success(), "{command} --json succeeds");
        assert_clean(&format!("{command} (json)"), &json);
        let response: Value =
            serde_json::from_slice(&json.stdout).expect("stdout is one JSON object");
        assert_bounded(&format!("{command} (json)"), &response, None);
    }

    // `extract` reports the object references a dossier chose and the media
    // type it declared, so it is held to the same rule.
    let output_dir = directory.path().join("out");
    let json = run(&[
        "extract",
        file,
        "--output",
        output_dir.to_str().expect("the path is UTF-8"),
        "--document",
        "#0",
        "--json",
    ]);
    assert!(
        json.status.success(),
        "extract succeeds: {}",
        String::from_utf8_lossy(&json.stdout)
    );
    assert_clean("extract (json)", &json);
    let response: Value = serde_json::from_slice(&json.stdout).expect("stdout is one JSON object");
    assert_bounded("extract (json)", &response, None);
    // The file itself was written under the name the title asked for: the
    // envelope's `path` names something real, which is why it is not bounded.
    assert_eq!(response["data"]["extracted"][0]["path"], "hello.txt");
    assert!(output_dir.join("hello.txt").is_file());

    // And the human run of the same extraction.
    let second = directory.path().join("out2");
    let human = run(&[
        "extract",
        file,
        "--output",
        second.to_str().expect("the path is UTF-8"),
        "--document",
        "#0",
    ]);
    assert!(human.status.success(), "extract (human) succeeds");
    assert_clean("extract (human)", &human);
}

/// The values are stripped, not escaped and not dropped: what a reader can see
/// is still shown, and only what a terminal would act on is gone.
#[test]
fn the_visible_content_of_a_hostile_value_survives() {
    let directory = scratch();
    let path = write(directory.path(), "hostile.es3", &hostile_dossier());
    let output = run(&["list", path.to_str().expect("the path is UTF-8"), "--json"]);
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON object");
    let data = &response["data"];

    assert_eq!(data["dossier"]["title"], "OKtxt.exe");
    assert_eq!(data["dossier"]["category"], "electronic dossier");
    assert_eq!(data["documents"][0]["object_ref"], "DocObject1");
    assert_eq!(data["documents"][0]["mime_type"]["media_type"], "text");

    // The unbounded half is cut short inside its cap, and says so.
    let subtype = data["documents"][0]["mime_type"]["subtype"]
        .as_str()
        .expect("the subtype is a string");
    assert_eq!(subtype.chars().count(), MAX_DISPLAY_CHARS);
    assert!(subtype.ends_with("..."));

    // The human line carries exactly the same text, because it is rendered
    // from this very value.
    let human = run(&["list", path.to_str().expect("the path is UTF-8")]);
    let text = String::from_utf8(human.stdout).expect("the summary is UTF-8");
    assert!(text.contains("OKtxt.exe"), "the title is still shown");
    assert!(
        text.contains(subtype),
        "the human line shows the same value"
    );
}

/// A title long enough to be cut short by the ordinary cap is not: a real
/// dossier title runs past 128 characters, and shortening one would make the
/// tool wrong about its input rather than safe with it.
#[test]
fn a_long_title_is_held_to_the_wider_title_cap() {
    let directory = scratch();
    let long = "T".repeat(200);
    let xml = hostile_dossier().replace(&format!("OK{RLO}txt.exe"), &long);
    let path = write(directory.path(), "long.es3", &xml);
    let output = run(&[
        "inspect",
        path.to_str().expect("the path is UTF-8"),
        "--json",
    ]);
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON object");
    assert_eq!(response["data"]["dossier"]["title"], long);

    let longer = "T".repeat(400);
    let xml = hostile_dossier().replace(&format!("OK{RLO}txt.exe"), &longer);
    let path = write(directory.path(), "longer.es3", &xml);
    let output = run(&[
        "inspect",
        path.to_str().expect("the path is UTF-8"),
        "--json",
    ]);
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("stdout is one JSON object");
    let title = response["data"]["dossier"]["title"]
        .as_str()
        .expect("the title is a string");
    assert_eq!(title.chars().count(), MAX_TITLE_CHARS);
    assert!(title.ends_with("..."));
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// A certificate's subject and issuer common names are text a CA wrote, and a
/// hostile dossier can carry any certificate it likes. The names reach the
/// verify report, so they are stripped there too.
///
/// The certificates are generated in this test rather than committed: a
/// certificate whose subject carries an invisible character is exactly the
/// thing a reviewer cannot see in a fixture.
#[test]
fn a_certificate_common_name_with_an_override_is_reported_stripped() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca(
            &format!("openSzigno Test{RLO} Root CA"),
            BasicConstraints::Unconstrained,
        ),
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer(&format!("openSzigno Test{RLO} Signer")),
        &signer_key,
        &root,
        &root_key,
    );

    let signature: SigSpec = document_signature(vec![signer.der.clone(), root.der.clone()]);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = common::build(&spec, &[("doc", &signer_key)]);

    let directory = scratch();
    let path = write(directory.path(), "signed.es3", &xml);
    let file = path.to_str().expect("the path is UTF-8");

    let json = run(&["verify", file, "--json", "--at", "2020-06-02T00:00:00Z"]);
    assert_clean("verify (json)", &json);
    let response: Value = serde_json::from_slice(&json.stdout).expect("stdout is one JSON object");
    assert_bounded("verify (json)", &response, None);

    // The name is still reported, and still says who it says: only the
    // character a terminal would act on is gone.
    let subject = response["data"]["signatures"][0]["signing_certificate"]["subject_cn"]
        .as_str()
        .expect("the signing certificate is summarised");
    assert_eq!(subject, "openSzigno Test Signer");
    assert!(!subject.contains(RLO));

    let human = run(&["verify", file, "--at", "2020-06-02T00:00:00Z"]);
    assert_clean("verify (human)", &human);
}
