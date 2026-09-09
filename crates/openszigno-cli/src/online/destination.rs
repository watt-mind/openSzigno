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
//!   otherwise. The list is exact: **loopback** (`127.0.0.0/8`, `::1`),
//!   **RFC 1918 private** (`10/8`, `172.16/12`, `192.168/16`),
//!   **link-local** (`169.254/16`, `fe80::/10`), **unique-local**
//!   (`fc00::/7`), **unspecified** (`0.0.0.0`, `::`, and the rest of
//!   `0.0.0.0/8`), **broadcast** (`255.255.255.255`), **multicast**
//!   (`224/4`, `ff00::/8`), the **cloud metadata** addresses
//!   `169.254.169.254` and `fd00:ec2::254`, and the name `localhost` (and any
//!   `*.localhost`). An IPv4-mapped IPv6 address is judged as the IPv4
//!   address it carries, so it is not a way round any of the above. A dossier
//!   that could point the verifier at `http://169.254.169.254/` or at a
//!   service on the operator's own subnet would have turned a signature check
//!   into a port scanner and an SSRF primitive.
//! - **The resolved address is checked too, and then connected to.** A public
//!   name that resolves to `127.0.0.1` — DNS rebinding, or simply a hostile
//!   zone — is refused on the address, not on the name. Every hop is checked:
//!   the URL out of the certificate and each redirect target the fetcher
//!   follows go through this module before a socket is opened. The lookup
//!   happens here **and its result is what is dialled**: [`permitted`] hands
//!   back the addresses it approved, and the fetcher pins them for `ureq`
//!   through [`super::pinned`], so there is no second lookup that could
//!   disagree with the first. A zone that answered with a public address and
//!   then with a private one used to have a window between the check and the
//!   socket; it no longer does.
//!
//! Pinning is an address decision only. The URL, and therefore the `Host`
//! header, the TLS SNI value and the certificate host-name verification, are
//! untouched: the peer still has to prove it is the name the certificate
//! published.
//!
//! Everything in this module is about *reaching* bytes. Nothing here decides
//! whether the bytes are believed: that is the verifier's, offline.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _};

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
const REFUSED_LITERAL: &str = "the host is a loopback, private, link-local, unique-local, unspecified or multicast address; pass --online-allow-private to permit it";
const REFUSED_RESOLVED: &str = "the host resolves to a loopback, private, link-local, unique-local, unspecified or multicast address; pass --online-allow-private to permit it";
const REFUSED_METADATA_LITERAL: &str = "the host is a cloud instance metadata address, which no certificate legitimately publishes; pass --online-allow-private to permit it";
const REFUSED_METADATA_RESOLVED: &str = "the host resolves to a cloud instance metadata address, which no certificate legitimately publishes; pass --online-allow-private to permit it";
/// The redirect rule: a hop that leaves `https` for `http` on the same host.
/// It is refused for every request kind, because a redirect is the peer's
/// choice and "keep talking, but in the clear" is not a choice a peer gets to
/// make for this tool.
pub(super) const REFUSED_REDIRECT_DOWNGRADE: &str = "redirect_downgrade: the redirect leaves https for http, and a peer does not get to move this request into the clear";
/// The credential rule: a request that carries a bearer token or a body the
/// caller flagged as sensitive, aimed at a URL that is not `https`.
pub(super) const REFUSED_PLAINTEXT_CREDENTIALS: &str = "credentials_require_https: the request carries credentials and the URL is not https; pass --online-allow-private to permit a loopback service";

/// The IPv4 link-local address every major cloud answers instance metadata on,
/// credentials included. It is inside `169.254.0.0/16` and so already refused;
/// it is named separately because a refusal that says *why* is the difference
/// between an operator shrugging and an operator looking at where their
/// dossier came from.
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
/// The IPv6 instance metadata address (`fd00:ec2::254`), likewise inside a
/// range already refused.
const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// One endpoint the policy approved, and the addresses it approved for it.
///
/// This is what makes the check binding rather than advisory: the fetcher pins
/// exactly these addresses for exactly this `(host, port)` before it issues the
/// request, so the socket goes where the policy looked. `host` is lower-cased
/// and carries no brackets around an IPv6 literal, which is the shape
/// [`super::pinned`] keys on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Vetted {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) addresses: Vec<SocketAddr>,
}

/// Whether one URL may be contacted, and on which addresses.
///
/// `allow_private` is `--online-allow-private`, which waives the address and
/// name rules and nothing else: a non-HTTP scheme and a URL with userinfo stay
/// refused whatever the flag says, because neither is a network-reachability
/// question. The flag does not waive *resolution*: an address is still needed
/// to connect to, so a host that resolves to nothing is `Unresolvable` with the
/// flag exactly as without it.
pub(super) fn permitted(url: &str, allow_private: bool) -> Result<Vetted, Refusal> {
    let scheme = scheme_of(url).ok_or(Refusal::Refused(REFUSED_SCHEME))?;
    if !matches!(scheme, "http" | "https") {
        return Err(Refusal::Refused(REFUSED_SCHEME));
    }
    let authority = host_of(url).ok_or(Refusal::Refused(REFUSED_NO_HOST))?;
    if authority.contains('@') {
        return Err(Refusal::Refused(REFUSED_USERINFO));
    }
    let (host, port) = split_authority(&authority).ok_or(Refusal::Refused(REFUSED_NO_HOST))?;
    let port = port.unwrap_or(if scheme == "https" { 443 } else { 80 });
    let host = host.to_ascii_lowercase();
    if !allow_private && (host == "localhost" || host.ends_with(".localhost")) {
        return Err(Refusal::Refused(REFUSED_LOCALHOST));
    }
    if let Some(address) = literal_address(&host) {
        if !allow_private {
            match verdict(address) {
                Verdict::Metadata => return Err(Refusal::Refused(REFUSED_METADATA_LITERAL)),
                Verdict::Restricted => return Err(Refusal::Refused(REFUSED_LITERAL)),
                Verdict::Permitted => {}
            }
        }
        return Ok(Vetted {
            host,
            port,
            addresses: vec![SocketAddr::new(address, port)],
        });
    }
    let resolved = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| Refusal::Unresolvable)?;
    let mut addresses = Vec::new();
    for address in resolved {
        if !allow_private {
            match verdict(address.ip()) {
                Verdict::Metadata => return Err(Refusal::Refused(REFUSED_METADATA_RESOLVED)),
                Verdict::Restricted => return Err(Refusal::Refused(REFUSED_RESOLVED)),
                Verdict::Permitted => {}
            }
        }
        addresses.push(address);
    }
    if addresses.is_empty() {
        return Err(Refusal::Unresolvable);
    }
    Ok(Vetted {
        host,
        port,
        addresses,
    })
}

/// Whether every address the policy approved for this endpoint is a loopback
/// address.
///
/// It is asked of the *vetted* addresses rather than of the host text, so a
/// name that resolves to `127.0.0.1` counts and a name that resolves to one
/// loopback address and one public one does not. `--online-allow-private` plus
/// loopback is the one place this build sends credentials without TLS, and it
/// exists for the test servers in `crates/openszigno-cli/tests`, which are
/// plain HTTP on `127.0.0.1`.
pub(super) fn loopback_only(vetted: &Vetted) -> bool {
    !vetted.addresses.is_empty()
        && vetted.addresses.iter().all(|address| match address.ip() {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or_else(|| v6.is_loopback(), |mapped| mapped.is_loopback()),
        })
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

/// What the policy makes of one address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    Permitted,
    /// Refused by range.
    Restricted,
    /// Refused, and it is an instance metadata address — worth saying,
    /// because it is the destination an SSRF actually wants.
    Metadata,
}

/// Judge one address.
///
/// The ranges are the ones that make an SSRF worth attempting: the machine
/// itself, the operator's own network, the link-local range that carries cloud
/// metadata services, the group addresses that reach more than one host, and
/// the IPv6 equivalents of each.
fn verdict(address: IpAddr) -> Verdict {
    // An IPv4-mapped address is an IPv4 destination written the other way
    // round, and must not be a way past the IPv4 rules.
    let address = match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => IpAddr::V4(mapped),
            None => IpAddr::V6(v6),
        },
        other => other,
    };
    match address {
        IpAddr::V4(v4) if v4 == METADATA_V4 => Verdict::Metadata,
        IpAddr::V6(v6) if v6 == METADATA_V6 => Verdict::Metadata,
        IpAddr::V4(v4) if is_restricted_v4(v4) => Verdict::Restricted,
        IpAddr::V6(v6) if is_restricted_v6(v6) => Verdict::Restricted,
        _ => Verdict::Permitted,
    }
}

fn is_restricted_v4(address: Ipv4Addr) -> bool {
    address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        // 0.0.0.0/8, "this network", which some stacks route to the host.
        || address.octets()[0] == 0
}

fn is_restricted_v6(address: Ipv6Addr) -> bool {
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        // fc00::/7, unique local (RFC 4193).
        || (address.segments()[0] & 0xfe00) == 0xfc00
        // fe80::/10, link local (RFC 4291).
        || (address.segments()[0] & 0xffc0) == 0xfe80
}

/// Whether a host names an address the policy refuses. Tests only: the policy
/// itself goes through [`permitted`], which is the whole rule and not just the
/// address part of it.
#[cfg(test)]
fn restricted_literal(host: &str) -> bool {
    literal_address(host).is_some_and(|address| verdict(address) != Verdict::Permitted)
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

    /// The credential rule's one exemption is granted on the addresses the
    /// policy approved, not on the host text: a name that resolves to
    /// `127.0.0.1` counts, and one address out of the range is enough to lose
    /// it.
    #[test]
    fn loopback_only_judges_the_vetted_addresses() {
        let vetted = |addresses: Vec<SocketAddr>| Vetted {
            host: "service.test".to_owned(),
            port: 443,
            addresses,
        };
        assert!(loopback_only(&vetted(vec![
            "127.0.0.1:443".parse().expect("a socket address"),
            "[::1]:443".parse().expect("a socket address"),
            "[::ffff:127.0.0.1]:443".parse().expect("a socket address"),
        ])));
        assert!(!loopback_only(&vetted(vec![
            "127.0.0.1:443".parse().expect("a socket address"),
            "198.51.100.7:443".parse().expect("a socket address"),
        ])));
        assert!(!loopback_only(&vetted(Vec::new())));
    }

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
            "http://[::ffff:10.0.0.1]/ca.crl",
            "http://[::]/ca.crl",
            "http://255.255.255.255/ca.crl",
            "http://224.0.0.1/ca.crl",
            "http://239.255.255.250/ca.crl",
            "http://[ff02::1]/ca.crl",
            "http://localhost/ca.crl",
            "http://LOCALHOST:8080/ca.crl",
        ] {
            assert!(
                matches!(permitted(url, false), Err(Refusal::Refused(_))),
                "{url} must be refused"
            );
            // With the flag the same URL is a destination like any other; the
            // loopback tests in tests/online.rs depend on exactly this.
            assert!(permitted(url, true).is_ok(), "{url} with the flag");
        }
    }

    #[test]
    fn a_public_literal_is_permitted() {
        assert!(permitted("http://93.184.216.34/ca.crl", false).is_ok());
        assert!(permitted("http://[2001:db8::1]/ca.crl", false).is_ok());
    }

    /// A literal is vetted without a lookup, and what comes back is the exact
    /// endpoint the fetcher will pin: the address the URL named, on the port it
    /// named or the scheme's default.
    #[test]
    fn a_vetted_literal_carries_the_address_that_will_be_dialled() {
        let vetted = permitted("http://93.184.216.34/ca.crl", false).expect("permitted");
        assert_eq!(vetted.host, "93.184.216.34");
        assert_eq!(vetted.port, 80);
        assert_eq!(
            vetted.addresses,
            vec![
                "93.184.216.34:80"
                    .parse::<SocketAddr>()
                    .expect("an address")
            ]
        );

        let vetted = permitted("https://[2001:DB8::1]:8443/ca.crl", false).expect("permitted");
        // The bracket-free, lower-case form is the one the resolver keys on.
        assert_eq!(vetted.host, "2001:db8::1");
        assert_eq!(vetted.port, 8443);
        assert_eq!(
            vetted.addresses,
            vec![
                "[2001:db8::1]:8443"
                    .parse::<SocketAddr>()
                    .expect("an address")
            ]
        );

        // The scheme decides the port when the URL does not name one.
        assert_eq!(
            permitted("https://93.184.216.34/ca.crl", false)
                .expect("permitted")
                .port,
            443
        );
    }

    /// Loopback with the flag is the test suite's own case, and it has to come
    /// back with an address to connect to, not merely with permission.
    #[test]
    fn loopback_with_the_flag_is_vetted_down_to_the_address() {
        let vetted = permitted("http://127.0.0.1:8080/ca.crl", true).expect("permitted");
        assert_eq!(vetted.host, "127.0.0.1");
        assert_eq!(vetted.port, 8080);
        assert_eq!(
            vetted.addresses,
            vec!["127.0.0.1:8080".parse::<SocketAddr>().expect("an address")]
        );
    }

    /// The metadata addresses are refused, and the refusal says which they
    /// are: it is the destination an SSRF is usually after, and an operator
    /// who sees it named in a report has learned something specific.
    #[test]
    fn the_cloud_metadata_addresses_are_named_when_refused() {
        for url in [
            "http://169.254.169.254/latest/meta-data",
            "http://[fd00:ec2::254]/latest/meta-data",
            "http://[::ffff:169.254.169.254]/latest/meta-data",
        ] {
            assert_eq!(
                permitted(url, false),
                Err(Refusal::Refused(REFUSED_METADATA_LITERAL)),
                "{url}"
            );
            assert!(permitted(url, true).is_ok(), "{url} with the flag");
        }
    }

    #[test]
    fn the_restricted_ranges_are_the_documented_ones() {
        assert!(restricted_literal("127.0.0.1"));
        assert!(restricted_literal("::1"));
        assert!(restricted_literal("fc00::1"));
        assert!(restricted_literal("fdff::1"));
        assert!(restricted_literal("fe80::1"));
        assert!(restricted_literal("10.0.0.1"));
        assert!(restricted_literal("172.16.0.1"));
        assert!(restricted_literal("192.168.0.1"));
        assert!(restricted_literal("169.254.169.254"));
        assert!(restricted_literal("fd00:ec2::254"));
        assert!(restricted_literal("224.0.0.1"));
        assert!(restricted_literal("ff02::1"));
        assert!(restricted_literal("0.0.0.0"));
        assert!(restricted_literal("::"));
        assert!(restricted_literal("255.255.255.255"));
        assert!(!restricted_literal("2606:4700::1111"));
        assert!(!restricted_literal("8.8.8.8"));
        assert!(!restricted_literal("172.32.0.1"));
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
