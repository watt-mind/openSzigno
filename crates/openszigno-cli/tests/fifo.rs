//! A named pipe named where a regular file is expected must be refused, not
//! waited on.
//!
//! Opening a FIFO for reading blocks inside `open(2)` until somebody opens the
//! writing end. That end belongs to whoever laid the pipe, so a dossier path
//! or a `--decrypt-key` pointing at one used to park the process for as long
//! as the other side liked, before the "is this a regular file?" check could
//! ever run. The reader now opens non-blocking, checks the type on the open
//! descriptor, and refuses anything that is not a regular file.
//!
//! Every test here is bounded: the child is spawned, polled for a few seconds,
//! and killed and failed if it is still running. A regression would otherwise
//! hang the test run rather than fail it.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// How long a refusal is allowed to take. Generous for a loaded CI machine and
/// still far below "waiting for a writer that will never come".
const DEADLINE: Duration = Duration::from_secs(10);

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// Create a FIFO with no writer, using the POSIX tool of the same name so the
/// test needs no extra dependency.
fn fifo(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(name);
    let status = Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo must be available on a Unix host");
    assert!(status.success(), "mkfifo must create the pipe");
    path
}

/// Wait for a spawned run to finish inside [`DEADLINE`], returning its output.
///
/// A run that is still going when the deadline passes is killed and the test
/// fails: that is exactly the hang this file exists to catch.
fn finish_within(mut child: Child, what: &str) -> (i32, Value) {
    let started = Instant::now();
    loop {
        match child.try_wait().expect("the child must be waitable") {
            Some(_) => break,
            None if started.elapsed() >= DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{what} did not finish within {DEADLINE:?}; it blocked on the pipe");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let output = child
        .wait_with_output()
        .expect("the finished child must yield its output");
    let status = output.status.code().expect("the child must exit normally");
    let json = serde_json::from_slice(&output.stdout).expect("stdout must be one JSON value");
    (status, json)
}

fn spawn(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the CLI must start")
}

#[test]
fn a_fifo_named_as_the_input_is_refused_rather_than_waited_on() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let pipe = fifo(directory.path(), "input.es3");

    let child = spawn(&["inspect", pipe.to_str().expect("a UTF-8 path"), "--json"]);
    let (status, json) = finish_within(child, "inspect on a FIFO");

    assert_eq!(status, 3, "a FIFO input is an io_error");
    assert_eq!(json["ok"], Value::Bool(false));
    assert_eq!(json["errors"][0]["code"], "io_error");
}

#[test]
fn a_fifo_named_as_the_decrypt_key_is_refused_rather_than_waited_on() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let pipe = fifo(directory.path(), "key.pem");
    let output = directory.path().join("out");

    let child = spawn(&[
        "extract",
        fixture("encrypted.es3").to_str().expect("a UTF-8 path"),
        "--output",
        output.to_str().expect("a UTF-8 path"),
        "--decrypt-key",
        pipe.to_str().expect("a UTF-8 path"),
        "--decrypt-cert",
        pipe.to_str().expect("a UTF-8 path"),
        "--json",
    ]);
    let (status, json) = finish_within(child, "extract --decrypt-key on a FIFO");

    assert_eq!(status, 3, "a FIFO key file is an io_error");
    assert_eq!(json["ok"], Value::Bool(false));
    assert_eq!(json["errors"][0]["code"], "io_error");
}
