//! Fuzz the `--online` destination policy: the module that decides, for a URL
//! that came out of a certificate nobody has established trust in yet, whether
//! a socket may be opened and to which addresses.
//!
//! The module lives in the `openszigno` binary crate, which has no library
//! target to depend on, so it is included here by path. It draws on nothing
//! but `std`, so what is fuzzed is the shipped source itself rather than a
//! copy of it — the point of the exercise.
//!
//! What is asserted, beyond "no panic":
//!
//! - **`permitted` never approves an address its own `verdict` refuses.** That
//!   is the whole policy in one sentence: whichever route a URL takes through
//!   the parser, every address handed back for the fetcher to pin has to be
//!   one the address rules allow. Without the flag, of course —
//!   `--online-allow-private` waives the address rules deliberately.
//! - **The refusals that are not reachability questions hold whatever the flag
//!   says**: a non-HTTP scheme and a URL carrying userinfo are refused with
//!   the flag exactly as without it.
//! - **`host_of` and `resolve` agree.** A `Location` resolved against a base
//!   URL stays on the base's authority unless it was absolute, which is the
//!   property the "a redirect to another host is another destination" rule is
//!   written against. There is no URL crate in this tree to check the parse
//!   against, so the invariants are stated here in full.
//!
//! **No lookup here reaches the network.** `permitted` resolves a host that is
//! not an IP literal, so the target runs it only when the authority parses as
//! a literal (or is `localhost`, which the policy answers by name). Everything
//! else exercises the parsing and the two absolute refusals, which are decided
//! before any resolution.

#![no_main]

use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;

#[allow(dead_code)]
#[path = "../../crates/openszigno-cli/src/online/destination.rs"]
mod destination;

use destination::{Refusal, Verdict, host_of, permitted, resolve, scheme_of, split_authority};

/// Whether `permitted` would answer this URL without a DNS lookup.
fn is_resolution_free(url: &str) -> bool {
    let Some(authority) = host_of(url) else {
        return false;
    };
    if authority.contains('@') {
        // Refused on the userinfo rule, before any resolution.
        return true;
    }
    let Some((host, _)) = split_authority(&authority) else {
        return true;
    };
    host == "localhost" || host.ends_with(".localhost") || host.parse::<IpAddr>().is_ok()
}

fuzz_target!(|data: &[u8]| {
    // A URL longer than this says nothing new about the parser.
    if data.len() > 512 {
        return;
    }
    let Ok(url) = std::str::from_utf8(data) else {
        return;
    };

    // The two rules that are not reachability questions are absolute: the flag
    // waives the address and name rules, and nothing else. Both are decided
    // before resolution, so this runs for every input.
    let scheme_is_http = matches!(scheme_of(url), Some("http" | "https"));
    let has_userinfo = host_of(url).is_some_and(|authority| authority.contains('@'));
    if !scheme_is_http || has_userinfo {
        assert!(
            matches!(permitted(url, true), Err(Refusal::Refused(_))),
            "{url:?} must be refused whatever the flag says"
        );
    }

    if is_resolution_free(url) {
        // The invariant the fetcher rests on: everything `permitted` hands
        // back is an address the policy's own verdict allows.
        if let Ok(vetted) = permitted(url, false) {
            for address in &vetted.addresses {
                assert_eq!(
                    destination::verdict(address.ip()),
                    Verdict::Permitted,
                    "permitted() approved {address} for {url:?}, which verdict() refuses"
                );
                assert_eq!(
                    address.port(),
                    vetted.port,
                    "every vetted address carries the endpoint's port"
                );
            }
            assert!(
                !vetted.addresses.is_empty(),
                "a vetted endpoint always carries an address to dial"
            );
            assert!(
                !vetted.host.is_empty(),
                "a vetted endpoint always names a host"
            );
            assert_eq!(
                vetted.host,
                vetted.host.to_ascii_lowercase(),
                "the pinned host is the lower-cased form the resolver keys on"
            );
            assert!(
                !vetted.host.starts_with('['),
                "the pinned host carries no brackets around an IPv6 literal"
            );
        }
        // With the flag, the same URL may be permitted where it was refused,
        // but never refused where it was permitted: the flag only ever widens.
        if permitted(url, false).is_ok() {
            assert!(
                permitted(url, true).is_ok(),
                "--online-allow-private must not refuse what the default permits: {url:?}"
            );
        }
    }

    // `resolve` against the URL it came from: a relative location stays on the
    // base's authority, an absolute one is taken as written.
    if url.contains("://") {
        for location in [
            "/other.crl",
            "other.crl",
            "",
            "   ",
            "https://other.example/x",
        ] {
            let Some(next) = resolve(url, location) else {
                continue;
            };
            if location.contains("://") {
                assert_eq!(next, location, "an absolute Location is taken as written");
            } else {
                assert_eq!(
                    host_of(&next),
                    host_of(url),
                    "a relative Location must stay on the base authority"
                );
            }
        }
    }
});
