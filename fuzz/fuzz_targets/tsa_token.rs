//! Fuzz RFC 3161 timestamp token parsing via
//! `openszigno_verify::tsa::token_certificates`, which accepts a bare CMS
//! `ContentInfo` or a whole `TimeStampResp` (see `crates/openszigno-verify/
//! src/tsa/token.rs`) and never trusts or validates anything it finds; it is
//! also internally bounded by `MAX_TOKEN_BYTES`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openszigno_verify::tsa::token_certificates;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let _ = token_certificates(data);
});
