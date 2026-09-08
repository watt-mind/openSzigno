//! Fuzz `openszigno_core::sniff`, the cheap pre-parse type detector.
//!
//! `sniff` never returns a `Result`; it always classifies. The only property
//! asserted here is "never panics".

#![no_main]

use libfuzzer_sys::fuzz_target;
use openszigno_core::sniff;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    let _ = sniff(data);
});
