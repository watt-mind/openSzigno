//! Fuzz `openszigno_core::parse` with both the default resource limits and a
//! deliberately tiny set of limits, so both the ordinary parse path and every
//! early-bailout limit check get exercised.
//!
//! The only property asserted is "never panics": `parse` returning `Err` for
//! malformed or hostile input is the documented, correct behaviour.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openszigno_core::{Limits, parse};

fn tiny_limits() -> Limits {
    Limits {
        max_input_bytes: 64 * 1024,
        max_documents: 4,
        max_base64_chars: 4 * 1024,
        max_decoded_document_bytes: 4 * 1024,
        max_total_decoded_bytes: 16 * 1024,
        max_zip_members: 2,
        max_zip_expanded_bytes: 4 * 1024,
        max_zip_compression_ratio: 10,
        max_xml_depth: 8,
        max_xml_nodes: 256,
    }
}

fuzz_target!(|data: &[u8]| {
    // Bound the input itself: cargo-fuzz's default -max_len already keeps
    // this well under a second per run, but a committed corpus entry could
    // in principle grow. Anything past 1 MiB is rejected by `max_input_bytes`
    // anyway, so skip the work of getting there.
    if data.len() > 1024 * 1024 {
        return;
    }

    let default_limits = Limits::default();
    let _ = parse(data, &default_limits);

    let tiny = tiny_limits();
    let _ = parse(data, &tiny);
});
