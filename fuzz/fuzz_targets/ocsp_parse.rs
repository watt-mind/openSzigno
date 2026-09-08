//! Fuzz OCSP response parsing via `openszigno_verify::revocation::classify`,
//! the exact function a revocation store loader runs over every file it is
//! given (DER, or PEM with an `OCSP RESPONSE` label). See `crl_parse` for the
//! CRL side of the same function.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openszigno_verify::revocation::classify;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let _ = classify(data);
});
