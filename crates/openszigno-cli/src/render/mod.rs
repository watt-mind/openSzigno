//! Writing a finished response out: the JSON envelope, the human summary,
//! the raw payload stream, and the diagnostics that go to stderr.

pub(crate) mod human;
pub(crate) mod json;

use std::io::{self, Write};

/// Write raw payload bytes to stdout, byte for byte and with nothing added.
/// A closed or failing stdout is an I/O failure the caller turns into exit
/// status 3, never a panic.
pub(crate) fn write_payload(bytes: &[u8]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(bytes)?;
    stdout.flush()
}

/// Best-effort diagnostic on stderr; a failing stderr must not abort the run.
pub(crate) fn write_diagnostic(line: &str) {
    let _ = writeln!(io::stderr(), "{line}");
}
