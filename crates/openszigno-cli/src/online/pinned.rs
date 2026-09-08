//! Connecting to the addresses the destination policy actually vetted.
//!
//! The destination policy in [`super::destination`] decides whether an address
//! may be contacted. Deciding is not the same as connecting: a policy that
//! looks a name up, approves what came back, and then hands the *name* to the
//! HTTP client has left the client to look it up a second time, and the two
//! answers need not agree. A hostile zone that returns a public address first
//! and `127.0.0.1` second walks straight past the address rules, and no amount
//! of care in the policy closes that gap, because the gap is between the check
//! and the socket rather than inside the check.
//!
//! So the check and the socket are joined here. `ureq` resolves names through
//! a [`Resolver`], which is pluggable, and this module supplies one that
//! resolves nothing: it answers from a map the fetcher writes immediately
//! after the policy has approved a hop, and it answers `HostNotFound` for
//! every name that is not in that map. There is no fallback to the system
//! resolver, so a second lookup cannot happen and cannot disagree.
//!
//! The name is still the name. Pinning replaces the address lookup and
//! nothing else: `ureq` is given the original URL, so the `Host` header, the
//! TLS SNI value and the certificate host-name verification all still use the
//! host the certificate published. Pinning changes *where the socket goes*,
//! never *who the peer must prove it is*.
//!
//! # The proxy case
//!
//! With `--online-proxy` the request is sent to the proxy and the proxy
//! resolves the destination, so there is nothing local to pin: `ureq` asks
//! this resolver for the *proxy's* host, not for the URL's. A pinned map keyed
//! by destination would refuse that and break the flag, so a fetcher built
//! with a proxy marks the resolver `proxied` and an unpinned name falls
//! through to the system resolver. The destination policy still runs on the
//! URL, and still refuses a scheme, userinfo, a literal or a resolved address
//! it does not permit; what it can no longer promise is that the socket the
//! *proxy* opens goes where the policy looked. That is inherent in delegating
//! the connection, and it is why the flag is opt-in.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ureq::Error;
use ureq::http::Uri;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

use super::destination::Vetted;

/// The most addresses one endpoint may be dialled on, which is the capacity of
/// `ureq`'s own `ResolvedSocketAddrs`.
const MAX_PINNED_ADDRESSES: usize = 16;

/// The addresses one host and port may be contacted on.
///
/// Keyed by `(host, port)` because the port is part of what the policy
/// approved: a redirect to another port on the same name is another endpoint,
/// and the fetcher already treats it as one.
type Pins = HashMap<(String, u16), Vec<SocketAddr>>;

/// A resolver that answers only from what the destination policy vetted.
#[derive(Debug)]
pub(super) struct PinnedResolver {
    pins: Mutex<Pins>,
    /// Whether a proxy is configured. See the module comment: with a proxy the
    /// only name `ureq` asks about is the proxy's own, and refusing it would
    /// break `--online-proxy` outright.
    proxied: bool,
    fallback: DefaultResolver,
}

impl PinnedResolver {
    pub(super) fn new(proxied: bool) -> Self {
        Self {
            pins: Mutex::new(HashMap::new()),
            proxied,
            fallback: DefaultResolver::default(),
        }
    }

    /// Make `vetted` the only destination this resolver will answer for.
    ///
    /// The map is replaced rather than added to, so a hop can never be
    /// connected to on an address a previous hop happened to vet.
    pub(super) fn pin(&self, vetted: &Vetted) {
        let mut pins = self.lock();
        pins.clear();
        pins.insert((vetted.host.clone(), vetted.port), vetted.addresses.clone());
    }

    /// The addresses pinned for one host and port, if any.
    fn pinned(&self, host: &str, port: u16) -> Option<Vec<SocketAddr>> {
        self.lock().get(&(normalize(host), port)).cloned()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Pins> {
        // A poisoned map would mean a panic while a pin was being written.
        // Recovering the guard keeps the failure a fetch failure rather than a
        // second panic; the map is replaced wholesale on the next pin anyway.
        self.pins.lock().unwrap_or_else(|error| error.into_inner())
    }
}

/// The handle the agent is built with.
///
/// `ureq` takes the resolver by value and keeps it, and the fetcher has to
/// keep writing pins into the same one, so both hold an `Arc`. The newtype
/// exists only because the trait and `Arc` are both foreign.
#[derive(Clone, Debug)]
pub(super) struct SharedResolver(pub(super) Arc<PinnedResolver>);

impl Resolver for SharedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, Error> {
        let host = uri.host().ok_or(Error::HostNotFound)?;
        let port = uri
            .port_u16()
            .or_else(|| default_port(uri.scheme_str()))
            .ok_or(Error::HostNotFound)?;
        let Some(addresses) = self.0.pinned(host, port) else {
            if self.0.proxied {
                // The proxy's own host. See the module comment.
                return self.0.fallback.resolve(uri, config, timeout);
            }
            // Not a destination the policy approved for this fetch. There is
            // deliberately no lookup here: falling back to the system resolver
            // is the whole bug this module exists to close.
            return Err(Error::HostNotFound);
        };
        let mut result = self.empty();
        // `ResolvedSocketAddrs` is a fixed-capacity vector and pushing past it
        // panics, so the pinned list is truncated to what it can hold. A host
        // with more addresses than that is one where any of them would do.
        for address in addresses.into_iter().take(MAX_PINNED_ADDRESSES) {
            result.push(address);
        }
        if result.is_empty() {
            Err(Error::HostNotFound)
        } else {
            Ok(result)
        }
    }
}

/// The default port for a scheme, matching what the destination policy assumed
/// when it vetted the same URL.
fn default_port(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    }
}

/// The map key for a host.
///
/// `Uri::host` hands back an IPv6 literal in its bracketed form, and a name in
/// whatever case the URL was written in; the policy stores neither. Lower-case
/// and unbracketed is the one shape both sides agree on.
fn normalize(host: &str) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use ureq::config::Config;
    use ureq::unversioned::transport::time::Duration;

    use super::*;

    fn timeout() -> NextTimeout {
        NextTimeout {
            after: Duration::NotHappening,
            reason: ureq::Timeout::Global,
        }
    }

    fn resolve(resolver: &SharedResolver, url: &str) -> Result<Vec<SocketAddr>, Error> {
        let uri: Uri = url.parse().expect("a URI");
        resolver
            .resolve(&uri, &Config::default(), timeout())
            .map(|addresses| addresses.iter().copied().collect())
    }

    fn vetted(host: &str, port: u16, addresses: &[SocketAddr]) -> Vetted {
        Vetted {
            host: host.to_owned(),
            port,
            addresses: addresses.to_vec(),
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    /// The finding, as a test. The resolver hands back exactly the vetted
    /// addresses for the vetted endpoint, and refuses everything else rather
    /// than looking it up: a name the system resolves perfectly well gets
    /// `HostNotFound` because *this fetch* did not vet it.
    #[test]
    fn only_the_vetted_addresses_are_returned_and_nothing_else_resolves() {
        let inner = Arc::new(PinnedResolver::new(false));
        let resolver = SharedResolver(Arc::clone(&inner));
        let approved = [v4(93, 184, 216, 34, 80), v4(93, 184, 216, 35, 80)];
        inner.pin(&vetted("crl.example", 80, &approved));

        assert_eq!(
            resolve(&resolver, "http://crl.example/ca.crl").expect("the vetted endpoint resolves"),
            approved.to_vec()
        );
        // The system resolves every one of these; the policy vetted none of
        // them for this fetch, so none of them may be connected to.
        for url in [
            // Another name.
            "http://localhost/ca.crl",
            // A literal the system needs no DNS for at all.
            "http://127.0.0.1/ca.crl",
            // The vetted name on another port: another endpoint.
            "http://crl.example:8080/ca.crl",
            // The vetted name under a scheme whose default port differs.
            "https://crl.example/ca.crl",
        ] {
            assert!(
                matches!(resolve(&resolver, url), Err(Error::HostNotFound)),
                "{url} must not resolve"
            );
        }
    }

    /// Pinning replaces rather than accumulates, so the address a previous hop
    /// vetted is not still reachable on the next one.
    #[test]
    fn a_new_pin_retires_the_previous_one() {
        let inner = Arc::new(PinnedResolver::new(false));
        let resolver = SharedResolver(Arc::clone(&inner));
        inner.pin(&vetted("first.example", 80, &[v4(93, 184, 216, 34, 80)]));
        inner.pin(&vetted("second.example", 80, &[v4(93, 184, 216, 35, 80)]));

        assert!(matches!(
            resolve(&resolver, "http://first.example/ca.crl"),
            Err(Error::HostNotFound)
        ));
        assert_eq!(
            resolve(&resolver, "http://second.example/ca.crl").expect("the current pin resolves"),
            vec![v4(93, 184, 216, 35, 80)]
        );
    }

    /// The URL's case and an IPv6 literal's brackets are spelling, not
    /// identity: both sides have to agree on one key or a vetted endpoint
    /// would refuse itself.
    #[test]
    fn the_key_ignores_case_and_ipv6_brackets() {
        let inner = Arc::new(PinnedResolver::new(false));
        let resolver = SharedResolver(Arc::clone(&inner));
        inner.pin(&vetted("crl.example", 443, &[v4(93, 184, 216, 34, 443)]));
        assert!(resolve(&resolver, "https://CRL.EXAMPLE/ca.crl").is_ok());

        let address = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            80,
        );
        inner.pin(&vetted("2001:db8::1", 80, &[address]));
        assert_eq!(
            resolve(&resolver, "http://[2001:db8::1]/ca.crl").expect("the literal resolves"),
            vec![address]
        );
    }

    /// An empty vetted list is not a licence to look the name up; it is a
    /// destination with nowhere to connect.
    #[test]
    fn an_empty_vetted_list_resolves_to_nothing() {
        let inner = Arc::new(PinnedResolver::new(false));
        let resolver = SharedResolver(Arc::clone(&inner));
        inner.pin(&vetted("crl.example", 80, &[]));
        assert!(matches!(
            resolve(&resolver, "http://crl.example/ca.crl"),
            Err(Error::HostNotFound)
        ));
    }

    /// With a proxy the only name `ureq` asks about is the proxy's, so an
    /// unpinned name is looked up rather than refused. A pinned one still
    /// answers from the pin.
    #[test]
    fn a_proxied_resolver_still_answers_from_a_pin() {
        let inner = Arc::new(PinnedResolver::new(true));
        let resolver = SharedResolver(Arc::clone(&inner));
        inner.pin(&vetted("crl.example", 80, &[v4(93, 184, 216, 34, 80)]));
        assert_eq!(
            resolve(&resolver, "http://crl.example/ca.crl").expect("the pin answers"),
            vec![v4(93, 184, 216, 34, 80)]
        );
    }
}

/// Pinning where it is actually load-bearing: over a real socket, through the
/// real agent, against a listener bound on this machine.
///
/// The unit tests above hold the resolver honest in isolation. These hold the
/// *fetcher* honest, which is the thing the finding was about: the check and
/// the connection have to be the same decision.
#[cfg(test)]
mod socket_tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::time::Duration;

    use super::super::Fetcher;
    use super::*;

    /// Serve `replies` in order, one connection each, then stop.
    fn serve(listener: TcpListener, replies: Vec<String>) -> std::thread::JoinHandle<usize> {
        std::thread::spawn(move || {
            let mut served = 0;
            for reply in replies {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                served += 1;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut request = Vec::new();
                let mut buffer = [0_u8; 512];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => request.extend_from_slice(&buffer[..read]),
                    }
                }
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Write);
            }
            served
        })
    }

    fn body(payload: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )
    }

    fn redirect(location: &str) -> String {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }

    /// The first URL and the redirect target both go through the policy and
    /// both are dialled on the address the policy approved. Two connections
    /// arrive, which is only possible if the second hop was pinned as well: an
    /// unpinned hop cannot resolve at all.
    #[test]
    fn every_hop_is_dialled_on_the_address_the_policy_vetted() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = listener.local_addr().expect("the port is known");
        let server = serve(listener, vec![redirect("/next.crl"), body("pinned")]);

        // `--online-allow-private`, exactly as the online suites run: loopback
        // is where a synthetic PKI has to publish.
        let fetcher = Fetcher::new(None, true).expect("the fetcher builds");
        let fetched = fetcher
            .fetch(&format!("http://{address}/ca.crl"), None, 1024)
            .expect("the fetch succeeds");
        assert_eq!(fetched, b"pinned");
        assert_eq!(server.join().expect("the server thread ends"), 2);
    }

    /// The finding, over a socket. The agent is asked for a host the system
    /// resolves without any DNS at all — a loopback literal — while the pinned
    /// map holds a different endpoint. Nothing connects: the listener never
    /// accepts anything.
    #[test]
    fn an_unpinned_host_is_never_connected_to_even_though_the_system_resolves_it() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = listener.local_addr().expect("the port is known");
        listener
            .set_nonblocking(true)
            .expect("the listener is non-blocking");

        let fetcher = Fetcher::new(None, true).expect("the fetcher builds");
        // A vetted endpoint that is not the one about to be asked for.
        fetcher.resolver.pin(&Vetted {
            host: "crl.example".to_owned(),
            port: 80,
            addresses: vec!["93.184.216.34:80".parse().expect("an address")],
        });

        let error = fetcher
            .agent
            .get(format!("http://{address}/ca.crl"))
            .call()
            .expect_err("an unpinned host must not connect");
        assert!(matches!(error, ureq::Error::HostNotFound), "{error:?}");
        assert!(
            matches!(
                listener.accept(),
                Err(ref io) if io.kind() == std::io::ErrorKind::WouldBlock
            ),
            "not one connection may be opened"
        );
    }

    /// An empty vetted list is not "connect anywhere": it is nowhere to
    /// connect, and the listener that would have answered sees nothing.
    #[test]
    fn an_empty_vetted_list_opens_no_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = listener.local_addr().expect("the port is known");
        listener
            .set_nonblocking(true)
            .expect("the listener is non-blocking");

        let fetcher = Fetcher::new(None, true).expect("the fetcher builds");
        fetcher.resolver.pin(&Vetted {
            host: address.ip().to_string(),
            port: address.port(),
            addresses: Vec::new(),
        });

        assert!(
            fetcher
                .agent
                .get(format!("http://{address}/ca.crl"))
                .call()
                .is_err()
        );
        assert!(matches!(
            listener.accept(),
            Err(ref io) if io.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    /// `--online-proxy` still builds an agent, and its resolver is the proxied
    /// one: the proxy's own name has to be resolvable or the flag would be
    /// unusable. The destination policy still runs on the URL; the proxy is
    /// what opens the socket.
    #[test]
    fn a_proxied_fetcher_still_constructs() {
        let fetcher =
            Fetcher::new(Some("http://127.0.0.1:3128"), false).expect("a proxied fetcher builds");
        assert!(fetcher.resolver.proxied);
        // And an unusable proxy URL is still reported rather than ignored.
        assert!(Fetcher::new(Some("not a proxy"), false).is_err());
    }
}
