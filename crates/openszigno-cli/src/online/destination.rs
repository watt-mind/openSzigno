//! Where `--online` is allowed to connect.
//!
//! The URL comes out of a certificate, and until a path to a configured trust
//! anchor has been built that certificate is just bytes somebody handed the
//! tool. So the URL is treated as attacker-chosen and put through a
//! destination policy before a socket is opened:
//!
//! - **`http` and `https` only**, exactly as published. Every other scheme is
//!   refused rather than rewritten into one this build speaks.
//! - **No userinfo.** A `user:password@host` authority is a way of making a
//!   URL read as one host while naming another, and it is also credential
//!   material this tool has no business sending anywhere.
//! - **No private destinations**, unless `--online-allow-private` says
//!   otherwise: loopback, RFC 1918, link-local, unique-local, and the
//!   `localhost` name. A dossier that could point the verifier at
//!   `http://169.254.169.254/` or at a service on the operator's own subnet
//!   would have turned a signature check into a port scanner and an SSRF
//!   primitive.
//! - **The resolved address is checked too.** A public name that resolves to
//!   `127.0.0.1` — DNS rebinding, or simply a hostile zone — is refused on the
//!   address, not on the name. The lookup happens here and the connection is
//!   made by `ureq`, which resolves again, so this is a mitigation and not a
//!   proof; it is one of the reasons the flag exists at all.
//!
//! Everything in this module is about *reaching* bytes. Nothing here decides
//! whether the bytes are believed: that is the verifier's, offline.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs as _};

/// Why a destination was not contacted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Refusal {
    /// The policy refuses this destination. The text is the reason, and it is
    /// reported to the caller.
    Refused(&'static str),
    /// The host does not resolve. That is a fact about the network, not a
    /// policy decision, so it is reported as a transport failure.
    Unresolvable,
}

const REFUSED_SCHEME: &str = "the URL scheme is not http or https";
const REFUSED_NO_HOST: &str = "the URL names no host";
const REFUSED_USERINFO: &str = "the URL carries userinfo before the host";
const REFUSED_LOCALHOST: &str = "the host is localhost, which is not a destination a certificate legitimately publishes; pass --online-allow-private to permit it";
const REFUSED_LITERAL: &str = "the host is a loopback, private, link-local or unique-local address; pass --online-allow-private to permit it";
const REFUSED_RESOLVED: &str = "the host resolves to a loopback, private, link-local or unique-local address; pass --online-allow-private to permit it";

/// Whether one URL may be contacted.
///
/// `allow_private` is `--online-allow-private`, which waives the address and
/// name rules and nothing else: a non-HTTP scheme and a URL with userinfo stay
/// refused whatever the flag says, because neither is a network-reachability
/// question.
pub(super) fn permitted(url: &str, allow_private: bool) -> Result<(), Refusal> {
    let scheme = scheme_of(url).ok_or(Refusal::Refused(REFUSED_SCHEME))?;
    if !matches!(scheme, "http" | "https") {
        return Err(Refusal::Refused(REFUSED_SCHEME));
    }
    let authority = host_of(url).ok_or(Refusal::Refused(REFUSED_NO_HOST))?;
    if authority.contains('@') {
        return Err(Refusal::Refused(REFUSED_USERINFO));
    }
    let (host, port) = split_authority(&authority).ok_or(Refusal::Refused(REFUSED_NO_HOST))?;
    if allow_private {
        return Ok(());
    }
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return Err(Refusal::Refused(REFUSED_LOCALHOST));
    }
    if let Some(address) = literal_address(host) {
        return if is_restricted(address) {
            Err(Refusal::Refused(REFUSED_LITERAL))
        } else {
            Ok(())
        };
    }
    let port = port.unwrap_or(if scheme == "https" { 443 } else { 80 });
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|_| Refusal::Unresolvable)?;
    let mut any = false;
    for address in resolved {
        any = true;
        if is_restricted(address.ip()) {
            return Err(Refusal::Refused(REFUSED_RESOLVED));
        }
    }
    if any {
        Ok(())
    } else {
        Err(Refusal::Unresolvable)
    }
}

/// Split an authority into its host and optional port, understanding the
/// bracketed form an IPv6 literal has to be written in.
fn split_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        if inside.is_empty() {
            return None;
        }
        let port = match after {
            "" => None,
            other => Some(other.strip_prefix(':')?.parse().ok()?),
        };
        return Some((inside, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some((host, Some(port.parse().ok()?))),
        Some(_) => None,
        None if authority.is_empty() => None,
        None => Some((authority, None)),
    }
}

/// The IP address a host names literally, if it names one at all.
fn literal_address(host: &str) -> Option<IpAddr> {
    host.parse::<IpAddr>().ok()
}

/// Whether an address is one `--online` refuses to contact by default.
///
/// The ranges are the ones that make an SSRF worth attempting: the machine
/// itself, the operator's own network, the link-local range that carries cloud
/// metadata services, and the IPv6 equivalents of each.
fn is_restricted(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_restricted_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            // An IPv4-mapped address is an IPv4 destination written the other
            // way round, and must not be a way past the IPv4 rules.
            Some(mapped) => is_restricted_v4(mapped),
            None => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    // fc00::/7, unique local (RFC 4193).
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    // fe80::/10, link local (RFC 4291).
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        },
    }
}

fn is_restricted_v4(address: Ipv4Addr) -> bool {
    address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        // 0.0.0.0/8, "this network", which some stacks route to the host.
        || address.octets()[0] == 0
}

/// The `--online-allow-private` counterpart used only by tests and by the
/// documentation: the IPv6 literal forms this module understands.
#[cfg(test)]
fn restricted_literal(host: &str) -> bool {
    literal_address(host).is_some_and(is_restricted)
}

pub(super) fn scheme_of(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    if rest.is_empty() || scheme.is_empty() {
        return None;
    }
    Some(scheme)
}

/// The authority of a URL, lower-cased, which is what "the same host" means
/// here. The port is part of it: a redirect to another port on the same name
/// is another endpoint.
pub(super) fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|value| !value.is_empty())?;
    Some(authority.to_ascii_lowercase())
}

/// Resolve a `Location` header against the URL it came from.
///
/// Only the two forms a real CA server uses are handled — an absolute URL and
/// a root-relative path — because anything else would be guesswork, and a
/// redirect this function refuses to resolve is reported rather than followed.
pub(super) fn resolve(base: &str, location: &str) -> Option<String> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    if location.contains("://") {
        return Some(location.to_owned());
    }
    let (scheme, rest) = base.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if let Some(path) = location.strip_prefix('/') {
        return Some(format!("{scheme}://{authority}/{path}"));
    }
    let directory = rest
        .split(['?', '#'])
        .next()
        .and_then(|path| path.rfind('/').map(|index| &path[..index]))
        .unwrap_or(authority);
    Some(format!("{scheme}://{directory}/{location}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_redirect_to_another_host_is_not_resolved_as_the_same_host() {
        let base = "http://crl.example/ca.crl";
        let next = resolve(base, "http://evil.example/ca.crl").expect("resolves");
        assert_ne!(host_of(&next), host_of(base));
    }

    #[test]
    fn a_root_relative_redirect_stays_on_the_same_host() {
        let base = "http://crl.example/pki/ca.crl";
        let next = resolve(base, "/other.crl").expect("resolves");
        assert_eq!(next, "http://crl.example/other.crl");
        assert_eq!(host_of(&next), host_of(base));
    }

    #[test]
    fn a_relative_redirect_is_resolved_against_the_directory() {
        let next = resolve("http://crl.example/pki/ca.crl", "new.crl").expect("resolves");
        assert_eq!(next, "http://crl.example/pki/new.crl");
    }

    #[test]
    fn a_different_port_is_a_different_host() {
        assert_ne!(
            host_of("http://crl.example/a"),
            host_of("http://crl.example:8080/a")
        );
    }

    #[test]
    fn only_http_schemes_are_recognised() {
        assert_eq!(scheme_of("ldap://directory.example/cn=ca"), Some("ldap"));
        assert_eq!(scheme_of("not a url"), None);
        assert_eq!(
            permitted("ldap://directory.example/cn=ca", true),
            Err(Refusal::Refused(REFUSED_SCHEME))
        );
        assert_eq!(
            permitted("file:///etc/passwd", true),
            Err(Refusal::Refused(REFUSED_SCHEME))
        );
    }

    /// Userinfo is refused whatever the flags say: it is not a reachability
    /// question, and no CA publishes a distribution point with credentials in
    /// it.
    #[test]
    fn userinfo_is_refused_even_with_the_flag() {
        for url in [
            "http://user:password@crl.example/ca.crl",
            "http://crl.example@127.0.0.1/ca.crl",
        ] {
            assert_eq!(
                permitted(url, true),
                Err(Refusal::Refused(REFUSED_USERINFO)),
                "{url}"
            );
        }
    }

    #[test]
    fn private_and_loopback_literals_are_refused_without_the_flag() {
        for url in [
            "http://127.0.0.1/ca.crl",
            "http://127.0.0.1:8080/ca.crl",
            "http://10.1.2.3/ca.crl",
            "http://172.16.0.1/ca.crl",
            "http://192.168.1.1/ca.crl",
            "http://169.254.169.254/latest/meta-data",
            "http://0.0.0.0/ca.crl",
            "http://[::1]/ca.crl",
            "http://[::1]:8080/ca.crl",
            "http://[fd00::1]/ca.crl",
            "http://[fe80::1]/ca.crl",
            "http://[::ffff:127.0.0.1]/ca.crl",
            "http://localhost/ca.crl",
            "http://LOCALHOST:8080/ca.crl",
        ] {
            assert!(
                matches!(permitted(url, false), Err(Refusal::Refused(_))),
                "{url} must be refused"
            );
            // With the flag the same URL is a destination like any other; the
            // loopback tests in tests/online.rs depend on exactly this.
            assert_eq!(permitted(url, true), Ok(()), "{url} with the flag");
        }
    }

    #[test]
    fn a_public_literal_is_permitted() {
        assert_eq!(permitted("http://93.184.216.34/ca.crl", false), Ok(()));
        assert_eq!(permitted("http://[2001:db8::1]/ca.crl", false), Ok(()));
    }

    #[test]
    fn the_restricted_ranges_are_the_documented_ones() {
        assert!(restricted_literal("127.0.0.1"));
        assert!(restricted_literal("::1"));
        assert!(restricted_literal("fc00::1"));
        assert!(restricted_literal("fdff::1"));
        assert!(restricted_literal("fe80::1"));
        assert!(!restricted_literal("2606:4700::1111"));
        assert!(!restricted_literal("8.8.8.8"));
    }

    #[test]
    fn an_authority_splits_into_a_host_and_a_port() {
        assert_eq!(split_authority("crl.example"), Some(("crl.example", None)));
        assert_eq!(
            split_authority("crl.example:8080"),
            Some(("crl.example", Some(8080)))
        );
        assert_eq!(split_authority("[::1]:8080"), Some(("::1", Some(8080))));
        assert_eq!(split_authority("[::1]"), Some(("::1", None)));
        assert_eq!(split_authority(""), None);
    }
}
