//! The `skill` command: write the agent skill document the binary carries
//! to stdout, byte for byte and with nothing added.

use std::io;

use crate::render::write_payload;

/// The agent skill, embedded at build time so the single binary can hand it
/// out with no file alongside it. The copy under
/// `crates/openszigno-cli/skills/openszigno/` is the same bytes.
pub(crate) const SKILL: &str = include_str!("../../skills/openszigno/SKILL.md");

/// Write the skill to stdout. A closed or failing stdout is an I/O failure
/// the caller turns into exit status 3, as everywhere else.
pub(crate) fn skill() -> io::Result<()> {
    write_payload(SKILL.as_bytes())
}
