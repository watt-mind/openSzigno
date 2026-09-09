//! RFC 3161 timestamping, as bytes in and bytes out.
//!
//! This module builds a `TimeStampReq` and reads the `TimeStampResp` that
//! comes back. It opens no socket and knows no URL: the caller carries the
//! request to the timestamp authority and brings the answer back, which is
//! what keeps this crate free of I/O and keeps the destination policy, the
//! timeouts and the size caps in the one place that already owns them, the
//! CLI's `--online` transport.
//!
//! What is checked here is what the caller cannot check: that the answer is a
//! granted response, that it carries a token, and that the token stamps the
//! imprint that was asked about. A token about somebody else's digest is worse
//! than no token, because it would be embedded as if it said something.

use der::{Decode as _, Encode as _};
use openszigno_verify::tsa::{MessageImprint, PkiStatusInfo, TimeStampResp, TstInfo};
use sha2::{Digest as _, Sha256};
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::error::{SignError, SignErrorCode};

/// `id-sha256`.
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
/// `id-signedData`, the content type of a bare RFC 3161 token.
const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// The media type an RFC 3161 request is posted as.
pub const TIMESTAMP_QUERY_TYPE: &str = "application/timestamp-query";
/// The media type a timestamp authority answers with.
pub const TIMESTAMP_REPLY_TYPE: &str = "application/timestamp-reply";

/// RFC 3161 `TimeStampReq`.
///
/// No nonce is sent. A nonce defends against a replayed response, and the
/// imprint here is the digest of a `ds:SignatureValue` that has just been
/// produced for the first time: a replayed token would have to stamp that
/// exact imprint, which is the thing being asked about. Leaving it out keeps
/// the request one fixed function of the imprint, which is what makes a run
/// reproducible for a caller who keeps the token.
#[derive(der::Sequence)]
struct TimeStampReq {
    version: i32,
    message_imprint: MessageImprint,
    /// Ask the authority to include its certificate, so the token carries what
    /// a verifier needs to check the token's own signature.
    cert_req: bool,
}

fn tsa_failed(message: impl Into<String>) -> SignError {
    SignError::new(SignErrorCode::TsaFailed, message)
}

/// The DER `TimeStampReq` that asks for a token over `octets`.
///
/// `octets` are the canonicalized `ds:SignatureValue` element, which is what a
/// `xades:SignatureTimeStamp` covers; the imprint is their SHA-256 digest.
pub fn timestamp_request(octets: &[u8]) -> Result<Vec<u8>, SignError> {
    let imprint = imprint(octets)?;
    TimeStampReq {
        version: 1,
        message_imprint: imprint,
        cert_req: true,
    }
    .to_der()
    .map_err(|_| tsa_failed("the timestamp request could not be encoded"))
}

fn imprint(octets: &[u8]) -> Result<MessageImprint, SignError> {
    Ok(MessageImprint {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: OID_SHA256
                .parse()
                .map_err(|_| tsa_failed("the digest algorithm could not be encoded"))?,
            parameters: None,
        },
        hashed_message: der::asn1::OctetString::new(Sha256::digest(octets).to_vec())
            .map_err(|_| tsa_failed("the message imprint could not be encoded"))?,
    })
}

/// The `TimeStampToken` DER inside `response`, checked against the octets it
/// was asked to stamp.
///
/// Both wire shapes are accepted, because both occur: an RFC 3161
/// `TimeStampResp`, and the bare `TimeStampToken` — a CMS `ContentInfo` —
/// some authorities answer with. A `TimeStampResp` is unwrapped only when its
/// `PKIStatus` is `granted` (0) or `grantedWithMods` (1); reading the token
/// field of a rejection would turn a refusal into a timestamp.
pub fn timestamp_token(response: &[u8], octets: &[u8]) -> Result<Vec<u8>, SignError> {
    let token = unwrap_response(response)?;
    check_imprint(&token, octets)?;
    Ok(token)
}

fn unwrap_response(response: &[u8]) -> Result<Vec<u8>, SignError> {
    if let Ok(parsed) = TimeStampResp::from_der(response) {
        // A bare token is a `ContentInfo`, whose first field is an OID rather
        // than the `PKIStatusInfo` SEQUENCE, so the two shapes cannot be
        // confused for one another by a decoder that accepts either.
        return granted_token(&parsed);
    }
    let token = cms::content_info::ContentInfo::from_der(response)
        .map_err(|_| tsa_failed("the timestamp authority's answer is not an RFC 3161 response"))?;
    if token.content_type.to_string() != OID_SIGNED_DATA {
        return Err(tsa_failed(
            "the timestamp authority's answer is not a CMS SignedData token",
        ));
    }
    token
        .to_der()
        .map_err(|_| tsa_failed("the timestamp token could not be re-encoded"))
}

fn granted_token(response: &TimeStampResp) -> Result<Vec<u8>, SignError> {
    let PkiStatusInfo { status, .. } = response.status;
    // `granted` is 0 and `grantedWithMods` is 1; every other value, a
    // negative one included, is a refusal. `status > 1` read a negative
    // PKIStatus as granted and went on to embed whatever the answer carried.
    if !(0..=1).contains(&status) {
        return Err(tsa_failed(format!(
            "the timestamp authority refused the request (PKIStatus {status})"
        )));
    }
    response
        .time_stamp_token
        .as_ref()
        .ok_or_else(|| tsa_failed("the timestamp authority's answer carries no token"))?
        .to_der()
        .map_err(|_| tsa_failed("the timestamp token could not be re-encoded"))
}

/// The `genTime` a token claims, RFC 3339 UTC seconds.
///
/// It is read back out of the token this run embedded, so a report can say
/// what the authority stamped without the caller having to decode CMS. It is
/// what the token claims and nothing more: only `openszigno verify` decides
/// whether the authority is anybody, and a token that will not decode simply
/// has no time to report.
pub fn token_gen_time(token: &[u8]) -> Option<String> {
    let info = tst_info(token).ok()?;
    let seconds = i64::try_from(info.gen_time.to_unix_duration().as_secs()).ok()?;
    Some(openszigno_verify::format_rfc3339(seconds))
}

/// The `TSTInfo` a `TimeStampToken` encapsulates.
fn tst_info(token: &[u8]) -> Result<TstInfo, SignError> {
    let content = cms::content_info::ContentInfo::from_der(token)
        .map_err(|_| tsa_failed("the timestamp token is not a CMS ContentInfo"))?;
    let signed = content
        .content
        .decode_as::<cms::signed_data::SignedData>()
        .map_err(|_| tsa_failed("the timestamp token is not a CMS SignedData"))?;
    let econtent = signed
        .encap_content_info
        .econtent
        .ok_or_else(|| tsa_failed("the timestamp token carries no TSTInfo"))?;
    TstInfo::from_der(econtent.value())
        .map_err(|_| tsa_failed("the timestamp token's TSTInfo does not decode"))
}

/// The token stamps the digest that was asked about, and nothing else.
fn check_imprint(token: &[u8], octets: &[u8]) -> Result<(), SignError> {
    let info = tst_info(token)?;
    let expected = Sha256::digest(octets);
    if info.message_imprint.hash_algorithm.oid.to_string() != OID_SHA256
        || info.message_imprint.hashed_message.as_bytes() != &expected[..]
    {
        return Err(tsa_failed(
            "the timestamp token stamps a different message imprint than the one requested",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_carries_the_sha256_imprint_and_asks_for_the_certificate() {
        let der = timestamp_request(b"octets").expect("the request encodes");
        let parsed = TimeStampReq::from_der(&der).expect("the request decodes");
        assert_eq!(parsed.version, 1);
        assert!(parsed.cert_req);
        assert_eq!(
            parsed.message_imprint.hashed_message.as_bytes(),
            &Sha256::digest(b"octets")[..]
        );
        assert_eq!(
            parsed.message_imprint.hash_algorithm.oid.to_string(),
            OID_SHA256
        );
    }

    /// A token that will not decode has no time to report, and says so
    /// rather than inventing one.
    #[test]
    fn a_token_that_does_not_decode_has_no_gen_time() {
        assert_eq!(token_gen_time(b"not DER at all"), None);
    }

    #[test]
    fn garbage_from_the_authority_is_a_tsa_failure() {
        let error = timestamp_token(b"not DER at all", b"octets").expect_err("this is not a token");
        assert_eq!(error.code(), SignErrorCode::TsaFailed);
    }

    #[test]
    fn a_refusal_is_never_read_past() {
        let response = TimeStampResp {
            status: PkiStatusInfo {
                status: 2,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: None,
        }
        .to_der()
        .expect("the response encodes");
        let error = timestamp_token(&response, b"octets").expect_err("the request was refused");
        assert_eq!(error.code(), SignErrorCode::TsaFailed);
        assert!(error.message().contains("PKIStatus 2"));
    }

    /// RFC 3161 numbers `PKIStatus` from zero, so a negative value is not a
    /// status at all. It used to compare below the refusal threshold and be
    /// read as granted.
    #[test]
    fn a_negative_status_is_a_refusal_too() {
        let response = TimeStampResp {
            status: PkiStatusInfo {
                status: -1,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: None,
        }
        .to_der()
        .expect("the response encodes");
        let error = timestamp_token(&response, b"octets").expect_err("this is no grant");
        assert_eq!(error.code(), SignErrorCode::TsaFailed);
        assert!(error.message().contains("PKIStatus -1"));
    }

    #[test]
    fn a_granted_response_with_no_token_is_a_failure() {
        let response = TimeStampResp {
            status: PkiStatusInfo {
                status: 0,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: None,
        }
        .to_der()
        .expect("the response encodes");
        let error = timestamp_token(&response, b"octets").expect_err("there is no token");
        assert!(error.message().contains("carries no token"));
    }
}
