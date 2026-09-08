//! The single JSON envelope: one object on stdout, and nothing else.

use std::io::{self, Write};

use crate::response::Response;

/// Write the single JSON envelope. A closed or failing stdout is an I/O
/// failure the caller turns into exit status 3, never a panic.
pub(crate) fn write_json(response: &Response) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(response).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(&bytes)?;
    stdout.flush()
}
