//! RFC 5280 section 4.2.1.10 name-constraint processing.
//!
//! Fails closed throughout: a constraint form this validator does not
//! implement, a name it cannot parse, and a permitted subtree of a type the
//! certificate carries but does not match are all violations. The name forms
//! evaluated are dNSName, rfc822Name, uniformResourceIdentifier (its host
//! alone), iPAddress and directoryName; anything else is a violation rather
//! than a pass.

use der::Encode;
use x509_cert::ext::pkix::NameConstraints;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;

use crate::codes::CheckCode;

use super::ParsedCertificate;

/// RFC 5280 section 4.2.1.10 name-constraint processing.
///
/// Fails closed throughout: a constraint form this validator does not
/// implement, a name it cannot parse, and a permitted subtree of a type the
/// certificate carries but does not match are all violations.
pub(super) fn check_name_constraints(
    certificate: &ParsedCertificate,
    constraints: &NameConstraints,
) -> Result<(), (CheckCode, String)> {
    let violation = || {
        (
            CheckCode::CertNameConstraintViolation,
            "a certificate in the path violates a name constraint imposed by a CA".to_owned(),
        )
    };
    let subject = &certificate.certificate.tbs_certificate.subject;
    let alternatives = certificate
        .extension::<SubjectAltName>()
        .map_err(|()| {
            (
                CheckCode::CertMalformed,
                "a certificate in the path carries a malformed subjectAltName".to_owned(),
            )
        })?
        .map(|san| san.0)
        .unwrap_or_default();

    // Every name the certificate asserts, as (kind, GeneralName).
    let mut names: Vec<GeneralName> = alternatives;
    if !subject.0.is_empty() {
        names.push(GeneralName::DirectoryName(subject.clone()));
    }

    for subtrees in [
        &constraints.excluded_subtrees,
        &constraints.permitted_subtrees,
    ]
    .into_iter()
    .flatten()
    {
        for subtree in subtrees {
            // An unimplemented constraint form must not be ignored: it may be
            // the only thing standing between this certificate and a name it
            // is not entitled to.
            if kind_of(&subtree.base).is_none() {
                return Err(violation());
            }
            // `minimum` and `maximum` are not implemented; RFC 5280 says both
            // MUST be absent, so a certificate that uses them fails closed.
            if subtree.minimum != 0 || subtree.maximum.is_some() {
                return Err(violation());
            }
        }
    }

    if let Some(excluded) = &constraints.excluded_subtrees {
        for subtree in excluded {
            for name in &names {
                if matches_general(&subtree.base, name)? {
                    return Err(violation());
                }
            }
        }
    }

    if let Some(permitted) = &constraints.permitted_subtrees {
        for name in &names {
            let Some(kind) = kind_of(name) else {
                // A name form the validator cannot evaluate, under a
                // constrained CA, fails closed.
                return Err(violation());
            };
            let same_kind: Vec<_> = permitted
                .iter()
                .filter(|subtree| kind_of(&subtree.base) == Some(kind))
                .collect();
            if same_kind.is_empty() {
                // This name form is unconstrained.
                continue;
            }
            let mut matched = false;
            for subtree in same_kind {
                if matches_general(&subtree.base, name)? {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err(violation());
            }
        }
    }
    Ok(())
}

/// The name forms this validator can evaluate. Anything else is `None`, which
/// every caller turns into a violation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NameKind {
    Dns,
    Rfc822,
    Uri,
    Directory,
    IpAddress,
}

fn kind_of(name: &GeneralName) -> Option<NameKind> {
    match name {
        GeneralName::DnsName(_) => Some(NameKind::Dns),
        GeneralName::Rfc822Name(_) => Some(NameKind::Rfc822),
        GeneralName::UniformResourceIdentifier(_) => Some(NameKind::Uri),
        GeneralName::DirectoryName(_) => Some(NameKind::Directory),
        GeneralName::IpAddress(_) => Some(NameKind::IpAddress),
        _ => None,
    }
}

fn matches_general(base: &GeneralName, name: &GeneralName) -> Result<bool, (CheckCode, String)> {
    let violation = || {
        (
            CheckCode::CertNameConstraintViolation,
            "a certificate in the path carries a name a constraint could not be evaluated against"
                .to_owned(),
        )
    };
    Ok(match (base, name) {
        (GeneralName::DnsName(base), GeneralName::DnsName(value)) => {
            dns_matches(base.as_str(), value.as_str())
        }
        (GeneralName::Rfc822Name(base), GeneralName::Rfc822Name(value)) => {
            rfc822_matches(base.as_str(), value.as_str())
        }
        (
            GeneralName::UniformResourceIdentifier(base),
            GeneralName::UniformResourceIdentifier(value),
        ) => {
            // The host is the only part a URI constraint applies to. A URI
            // with no host, or one whose host is an IP literal, cannot satisfy
            // a DNS-style constraint, and is a violation rather than a pass.
            let host = uri_host(value.as_str()).ok_or_else(violation)?;
            if host.is_ip_literal {
                return Err(violation());
            }
            dns_matches(base.as_str(), &host.host)
        }
        (GeneralName::DirectoryName(_), GeneralName::DirectoryName(subject)) => {
            matches_directory(base, subject)
        }
        (GeneralName::IpAddress(base), GeneralName::IpAddress(value)) => {
            ip_matches(base.as_bytes(), value.as_bytes()).ok_or_else(violation)?
        }
        _ => false,
    })
}

/// RFC 5280 dNSName matching: an exact host match, or a match on a label
/// boundary. `example.com` matches `host.example.com` but never
/// `notexample.com`. A leading dot on the constraint is accepted and means the
/// same thing, minus the exact match.
fn dns_matches(base: &str, value: &str) -> bool {
    let (base, allow_exact) = match base.strip_prefix('.') {
        Some(stripped) => (stripped, false),
        None => (base, true),
    };
    if base.is_empty() {
        return true;
    }
    if allow_exact && value.eq_ignore_ascii_case(base) {
        return true;
    }
    value.len() > base.len()
        && value.as_bytes()[value.len() - base.len() - 1] == b'.'
        && value[value.len() - base.len()..].eq_ignore_ascii_case(base)
}

/// RFC 5280 rfc822Name matching: a constraint with a local part is an exact
/// mailbox, a bare host is the exact host part, and a leading dot matches any
/// mailbox in that domain or below it.
fn rfc822_matches(base: &str, value: &str) -> bool {
    if base.contains('@') {
        return base.eq_ignore_ascii_case(value);
    }
    let Some((_, domain)) = value.rsplit_once('@') else {
        return false;
    };
    if base.starts_with('.') {
        return dns_matches(base, domain);
    }
    domain.eq_ignore_ascii_case(base)
}

struct UriHost {
    host: String,
    is_ip_literal: bool,
}

/// The host component of an absolute URI, or `None` when there is none.
///
/// Deliberately small and strict: anything this cannot parse confidently is a
/// name the constraint could not be evaluated against, which the caller turns
/// into a violation rather than a pass.
fn uri_host(uri: &str) -> Option<UriHost> {
    let after_scheme = uri.split_once("://")?.1;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .filter(|value| !value.is_empty())?;
    // Drop userinfo, which is not part of the host.
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, rest)| rest);
    if let Some(rest) = authority.strip_prefix('[') {
        // An IPv6 literal.
        let host = rest.split_once(']')?.0;
        return Some(UriHost {
            host: host.to_owned(),
            is_ip_literal: true,
        });
    }
    let host = authority
        .split(':')
        .next()
        .filter(|value| !value.is_empty())?;
    let is_ip_literal = !host.is_empty()
        && host
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
        && host.split('.').count() == 4;
    Some(UriHost {
        host: host.to_owned(),
        is_ip_literal,
    })
}

/// An iPAddress constraint is an address followed by a mask of the same width.
/// `None` means the encoding is not one this validator understands, which the
/// caller turns into a violation.
fn ip_matches(base: &[u8], value: &[u8]) -> Option<bool> {
    let width = match base.len() {
        8 => 4,
        32 => 16,
        _ => return None,
    };
    if value.len() != width {
        // A v4 address is simply outside a v6 constraint, and the other way
        // round; that is a clean non-match, not an encoding this cannot read.
        return Some(false);
    }
    let (network, mask) = base.split_at(width);
    Some(
        network
            .iter()
            .zip(mask.iter())
            .zip(value.iter())
            .all(|((network, mask), value)| network & mask == value & mask),
    )
}

/// A directoryName constraint matches when the base is an RDN-wise prefix of
/// the subject, comparing each RDN by its DER encoding.
fn matches_directory(base: &GeneralName, subject: &Name) -> bool {
    let GeneralName::DirectoryName(base) = base else {
        return false;
    };
    if base.0.len() > subject.0.len() {
        return false;
    }
    base.0.iter().zip(subject.0.iter()).all(|(left, right)| {
        left.to_der().unwrap_or_default() == right.to_der().unwrap_or_default()
    })
}
