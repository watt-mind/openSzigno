//! The `skill` command: the binary hands out the agent skill it embeds, so
//! a single downloaded binary is enough to install the skill.

use std::process::{Command, Output};

/// The committed skill document, the same bytes the binary embeds.
const SKILL: &str = include_str!("../skills/openszigno/SKILL.md");

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(args)
        .output()
        .expect("CLI must run")
}

#[test]
fn skill_writes_the_embedded_document_to_stdout() {
    let output = run(&["skill"]);
    assert!(output.status.success(), "skill must exit 0");
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stderr.is_empty(),
        "skill must write nothing to stderr"
    );
    assert_eq!(
        output.stdout,
        SKILL.as_bytes(),
        "stdout must be the skill byte for byte"
    );
    assert!(
        SKILL.starts_with("---\nname: openszigno"),
        "the skill must keep its Agent Skills frontmatter"
    );
}

#[test]
fn skill_rejects_json() {
    let output = run(&["skill", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "skill takes no --json: that is a usage error"
    );
}
