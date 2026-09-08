//! Fuzz `openszigno_verify::trustlist::load`, the ETSI TS 119 612 trusted
//! list reader. Called with no signer certificates, which is a supported,
//! fully offline mode (`trust_list_unverified`), so the harness never needs
//! network access or a real LOTL signer to reach the list-body parsing this
//! target exists to exercise.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openszigno_verify::c14n::RoxmltreeC14n;
use openszigno_verify::trustlist::load;

fuzz_target!(|data: &[u8]| {
    if data.len() > 512 * 1024 {
        return;
    }
    let backend = RoxmltreeC14n;
    let _ = load(data, &[], &backend);
});
