//! The certificate that signed the list: what it is bound to, and what ETSI
//! TS 119 612 clause 5.7.1 says it has to look like.
//!
//! Two different questions live here, and they are answered at two different
//! strengths on purpose.
//!
//! The first is a **binding**: the list's XAdES-B-B signature carries a signed
//! `xades:SigningCertificateV2` (or, on an older list, `SigningCertificate`),
//! which is the scheme operator saying, inside the signed bytes, which
//! certificate signed. Annex B.1.1 of TS 119 612 V2.4.1 calls it "an effective
//! way of securing the scheme operator identifier". If the certificate the
//! caller supplied is not the one that property designates, the caller and the
//! list disagree about who signed, and this build refuses to decide which of
//! them is right: `trust_list_signer_mismatch` is `unknown`, so the list can
//! never support a `valid` verdict.
//!
//! The second is the set of restrictions clause 5.7.1 places on the scheme
//! operator's own certificate: a self-signed or listed issuer, a `KeyUsage` of
//! `digitalSignature` and/or `nonRepudiation`, `BasicConstraints` indicating
//! `CA=false`, and an `ExtendedKeyUsage` that "should be present containing
//! id-tsl-kp-tslSigning". Those are reported as `info`
//! (`trust_list_signer_unqualified`) and never block, for two reasons. The
//! clause makes the extended key usage a "should", not a "shall"; and the
//! European Commission's own LOTL signing certificate carries an
//! `extendedKeyUsage` of TLS client authentication and e-mail protection with
//! no `id-tsl-kp-tslSigning` in it at all, so a build that blocked on this
//! rule would refuse the one list every other list is bootstrapped from.
//! What makes the signature trustworthy here is the caller's out-of-band
//! certificate and the cryptography, not the scheme operator's hygiene.

use const_oid::ObjectIdentifier;
use openszigno_core::roxmltree::Node;

use crate::certs::{CertificateSource, ParsedCertificate, verify_issued_by};
use crate::codes::{Check, CheckCode};
use crate::references::ReferenceScope;
use crate::xades::{self, BindingFailure};

use super::parse::{decode_base64, is_tsl, text};

/// `id-tsl-kp-tslSigning`, ETSI TS 119 612 clause 5.7.1:
/// `{ itu-t(0) identified-organization(4) etsi(0) tsl-specification(2231)
/// kp(3) tsl-signing(0) }`.
const OID_TSL_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.2231.3.0");

/// The largest number of certificates read out of the list itself when asking
/// whether the signer was issued by something the list names. The list is
/// attacker-supplied until its signature verifies, and each candidate costs a
/// public-key operation.
const MAX_ISSUER_CANDIDATES: usize = 512;

/// Everything this build can say offline about the certificate that verified
/// the list's signature.
///
/// `scopes` are the effective node sets of the list signature's references, so
/// that only a `xades:SignedProperties` the signature actually digests is
/// read: an unsigned `ds:Object` says nothing and must decide nothing.
pub(super) fn signer_checks(
    root: Node<'_, '_>,
    signature: Node<'_, '_>,
    scopes: &[ReferenceScope],
    signer: &ParsedCertificate,
) -> Vec<Check> {
    let mut checks = Vec::new();
    if let Some(check) = binding_check(signature, scopes, signer) {
        checks.push(check);
    }
    checks.extend(restriction_checks(root, signer));
    checks
}

/// The signed `SigningCertificateV2` binding, when the list carries one.
///
/// A list that carries no such property at all is not reported: TLv5 lists
/// signed as XAdES-BES need not carry it, and the caller's certificate is
/// still what the signature was verified with.
fn binding_check(
    signature: Node<'_, '_>,
    scopes: &[ReferenceScope],
    signer: &ParsedCertificate,
) -> Option<Check> {
    let properties = xades::parse_covered(signature, scopes);
    properties.signing_certificate_form?;
    let candidates = std::slice::from_ref(signer);
    match xades::match_certificate(&properties.certificate_references, candidates, false) {
        Ok(_) => None,
        Err(failure) => Some(Check::unknown(
            CheckCode::TrustListSignerMismatch,
            match failure {
                BindingFailure::DigestAlgorithm => {
                    "the trusted list's signed SigningCertificate property names no digest algorithm inside the pinned allowlist, so what it designates cannot be established"
                }
                BindingFailure::IssuerSerial => {
                    "the supplied signer certificate digests to the trusted list's signed SigningCertificate property but its issuer and serial do not match"
                }
                BindingFailure::NoMatch => {
                    "the certificate supplied to verify the trusted list is not the one the list's own signed SigningCertificate property designates"
                }
            },
        )),
    }
}

/// The clause 5.7.1 restrictions on the TLSO certificate, each reported as
/// `info` and named by the requirement it failed.
fn restriction_checks(root: Node<'_, '_>, signer: &ParsedCertificate) -> Vec<Check> {
    let mut checks = Vec::new();
    let mut report = |message: &str| {
        checks.push(Check::info(CheckCode::TrustListSignerUnqualified, message));
    };

    match signer.extended_key_usages() {
        Ok(Some(usages)) if usages.contains(&OID_TSL_SIGNING) => {}
        Ok(Some(_)) => report(
            "ETSI TS 119 612 clause 5.7.1: the trusted list signer's extendedKeyUsage does not name id-tsl-kp-tslSigning (0.4.0.2231.3.0)",
        ),
        Ok(None) => report(
            "ETSI TS 119 612 clause 5.7.1: the trusted list signer carries no extendedKeyUsage, so nothing in it says the key may sign trusted lists",
        ),
        Err(()) => report(
            "ETSI TS 119 612 clause 5.7.1: the trusted list signer's extendedKeyUsage is present but malformed",
        ),
    }

    match signer.key_usage() {
        Ok(Some(usage)) if usage.digital_signature() || usage.non_repudiation() => {}
        Ok(Some(_)) => report(
            "ETSI TS 119 612 clause 5.7.1: the trusted list signer's keyUsage includes neither digitalSignature nor nonRepudiation",
        ),
        Ok(None) => {}
        Err(()) => report(
            "ETSI TS 119 612 clause 5.7.1: the trusted list signer's keyUsage is present but malformed",
        ),
    }

    match signer.basic_constraints() {
        Ok(Some(constraints)) if constraints.ca => report(
            "ETSI TS 119 612 clause 5.7.1: the trusted list signer's basicConstraints says CA=true, where the clause requires CA=false",
        ),
        Ok(_) => {}
        Err(()) => report(
            "ETSI TS 119 612 clause 5.7.1: the trusted list signer's basicConstraints is present but malformed",
        ),
    }

    if !signer.is_self_signed() && !issued_by_the_list(root, signer) {
        report(
            "ETSI TS 119 612 clause 5.7.1: the trusted list signer is neither self-signed nor issued by a certificate this list names; the clause also allows an issuer listed in another list of the same community, which cannot be checked from one file",
        );
    }

    checks
}

/// Whether any certificate the list itself carries issued the signer.
///
/// Clause 5.7.1 allows the issuer to be "a TSP trust service listed in the TL
/// or in one of the TL that is part of the same community". Only the first
/// half of that is answerable from one file, so only it is asked; the check is
/// `info` precisely because the other half stays unanswered.
fn issued_by_the_list(root: Node<'_, '_>, signer: &ParsedCertificate) -> bool {
    root.descendants()
        .filter(|node| {
            node.is_element() && node.tag_name().name() == "X509Certificate" && is_tsl(*node)
        })
        .take(MAX_ISSUER_CANDIDATES)
        .filter_map(|node| decode_base64(&text(node)))
        .filter_map(|der| ParsedCertificate::from_der(&der, CertificateSource::TrustList))
        .any(|issuer| verify_issued_by(signer, &issuer))
}
