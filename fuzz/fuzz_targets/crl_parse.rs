//! Fuzz CRL parsing via `openszigno_verify::revocation::classify`, the exact
//! function a revocation store loader runs over every file it is given
//! (DER or PEM, `X509 CRL` / `CRL` label). Also reachable from an OCSP
//! response, since `classify` tries a CRL parse first; `ocsp_parse` seeds a
//! separate corpus so both parsers get their own coverage-guided minimisation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openszigno_verify::revocation::classify;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let _ = classify(data);
});
