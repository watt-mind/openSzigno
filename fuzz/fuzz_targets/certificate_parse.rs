//! Fuzz X.509 certificate candidate parsing via
//! `openszigno_verify::certs::certificates_from_bytes`, exactly what a trust
//! or revocation store loader runs over every file it is given (PEM with one
//! or more `CERTIFICATE` blocks, or a single DER certificate).

#![no_main]

use libfuzzer_sys::fuzz_target;
use openszigno_verify::certs::certificates_from_bytes;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let _ = certificates_from_bytes(data);
});
