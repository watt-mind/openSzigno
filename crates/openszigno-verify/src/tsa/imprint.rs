//! The message imprint: the digest-algorithm allowlist a token may name, and
//! the recomputation that binds a token to the data it claims to cover.
//!
//! This is the step most often skipped, and the only one that ties a token to
//! this signature rather than to some other document the same TSA stamped.

use const_oid::ObjectIdentifier;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::codes::{Check, CheckCode};
use crate::policy::Digest;

use super::TokenInput;
use super::token::TstInfo;

pub(super) const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
pub(super) const OID_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub(super) const OID_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
pub(super) const OID_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// Recompute the imprint over the data the token claims to cover and report
/// whether it matches, returning the digest algorithm the token named.
pub(super) fn check_imprint(
    tst_info: &TstInfo,
    input: &TokenInput<'_>,
    checks: &mut Vec<Check>,
) -> Option<Digest> {
    // --- The imprint, which is what binds the token to this signature -------
    let imprint_algorithm = digest_of_oid(
        &tst_info.message_imprint.hash_algorithm.oid,
        input.allow_legacy_algorithms,
    );
    match imprint_algorithm {
        None => checks.push(Check::failed(
            CheckCode::TimestampImprintMismatch,
            "the message imprint names a digest algorithm outside the pinned allowlist",
        )),
        Some(algorithm) => {
            let computed = digest(algorithm, &input.imprint_input);
            if computed != tst_info.message_imprint.hashed_message.as_bytes() {
                checks.push(Check::failed(
                    CheckCode::TimestampImprintMismatch,
                    "the message imprint does not match the data the timestamp covers",
                ));
            } else if algorithm.is_legacy() {
                // Recomputing a SHA-1 imprint is diagnosis, not proof: a
                // second preimage would let the same token be claimed over
                // other data. `--allow-legacy-algorithms` asked to be shown
                // the answer, not to be told the token is verified, so this is
                // `unknown` and the token stays unverified.
                checks.push(Check::unknown(
                    CheckCode::AlgorithmLegacyAllowed,
                    "the message imprint names SHA-1 and matches the data the timestamp covers, admitted only because legacy algorithms were allowed; its strength is not vouched for",
                ));
            } else {
                checks.push(Check::passed(
                    CheckCode::TimestampImprintOk,
                    "the message imprint matches the data the timestamp covers",
                ));
            }
        }
    }
    imprint_algorithm
}

pub(super) fn digest_of_oid(
    oid: &ObjectIdentifier,
    allow_legacy_algorithms: bool,
) -> Option<Digest> {
    let digest = match *oid {
        OID_SHA1 => Digest::Sha1,
        OID_SHA256 => Digest::Sha256,
        OID_SHA384 => Digest::Sha384,
        OID_SHA512 => Digest::Sha512,
        _ => return None,
    };
    (!digest.is_legacy() || allow_legacy_algorithms).then_some(digest)
}

pub(super) fn digest(algorithm: Digest, bytes: &[u8]) -> Vec<u8> {
    match algorithm {
        Digest::Sha1 => Sha1::digest(bytes).to_vec(),
        Digest::Sha256 => Sha256::digest(bytes).to_vec(),
        Digest::Sha384 => Sha384::digest(bytes).to_vec(),
        Digest::Sha512 => Sha512::digest(bytes).to_vec(),
    }
}
