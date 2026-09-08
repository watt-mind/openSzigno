//! OCSP response validation and the RFC 6960 responder-authorisation models.
//!
//! The nonce is ignored throughout, because offline validation replays a
//! response produced for someone else's request; freshness and the `certID`
//! binding carry the weight instead.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};

use crate::certs::{ParsedCertificate, verify_der_signature};
use crate::codes::CheckCode;
use crate::policy::VerifyLimits;
use crate::trust::UnixTime;

use super::crl::reason_name;
use super::tiers::Answer;
use super::{covers, generalized};

const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// Which RFC 6960 model authorised the responder that answered.
///
/// RFC 6960 section 2.2 gives a relying party three ways to accept an OCSP
/// response, and openSzigno implements all three with a fixed precedence:
///
/// 1. **`issuer`** — the CA that issued the queried certificate signed the
///    response itself. Nothing more is needed and nothing weaker is preferred.
/// 2. **`delegated`** — a certificate that CA issued, carrying
///    `id-kp-OCSPSigning`, signed it. The CA's own signature over that
///    certificate is the delegation.
/// 3. **`trusted`** — the responder is one the *relying party* trusts
///    directly: its certificate carries `id-kp-OCSPSigning` and its path
///    validates to a configured trust anchor at `producedAt`, even though the
///    queried certificate's issuer never delegated to it.
///
/// The third exists because central responders are real. A national CA
/// operator commonly runs one responder for every CA in its hierarchy, issued
/// by a sibling CA rather than by whichever CA issued the certificate being
/// asked about; a verifier that implemented only the first two models rejects
/// every one of those answers as unauthorised. Its authority is the caller's
/// trust store, which is why it comes last: it rests on what the operator
/// configured rather than on what the issuing CA said.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponderModel {
    Issuer,
    Delegated,
    Trusted,
}

impl ResponderModel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::Delegated => "delegated",
            Self::Trusted => "trusted",
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn ocsp_answer(
    der: &[u8],
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    time: UnixTime,
    limits: &VerifyLimits,
) -> Answer {
    // An `EncapsulatedOCSPValue` holds a whole `OCSPResponse`; a store file may
    // hold either that or a bare `BasicOCSPResponse`.
    let basic = match OcspResponse::from_der(der) {
        Ok(response) => {
            if response.response_status != OcspResponseStatus::Successful {
                // A responder that reported a failure carries no status to
                // believe; reading past it would turn a refusal into an answer.
                return Answer::Invalid("its OCSPResponseStatus is not successful");
            }
            let Some(bytes) = response.response_bytes else {
                return Answer::Invalid("it carries no response bytes");
            };
            if bytes.response_type != const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC {
                return Answer::Invalid("its response type is not id-pkix-ocsp-basic");
            }
            match BasicOcspResponse::from_der(bytes.response.as_bytes()) {
                Ok(basic) => basic,
                Err(_) => return Answer::Invalid("its BasicOCSPResponse could not be decoded"),
            }
        }
        Err(_) => match BasicOcspResponse::from_der(der) {
            Ok(basic) => basic,
            Err(_) => return Answer::Invalid("it is not a decodable OCSP response"),
        },
    };

    let Some(single) = basic
        .tbs_response_data
        .responses
        .iter()
        .find(|single| cert_id_matches(&single.cert_id, subject, issuer))
    else {
        return Answer::NotApplicable;
    };

    let produced_at = generalized(&basic.tbs_response_data.produced_at.0);
    let Some(responder_model) = responder_authorised(
        &basic,
        issuer,
        candidates,
        anchors,
        produced_at,
        time,
        limits,
    ) else {
        return Answer::Invalid(
            "the responder is not the issuing CA, is not a responder that CA delegated to, and does not chain to a configured trust anchor as a trusted responder",
        );
    };
    let responder_model = Some(responder_model);

    let this_update = generalized(&single.this_update.0);
    let next_update = single.next_update.as_ref().map(|time| generalized(&time.0));
    if !covers(this_update, next_update, time) {
        return Answer::Stale;
    }

    match &single.cert_status {
        CertStatus::Good(_) => Answer::Good {
            this_update,
            next_update,
            produced_at: Some(produced_at),
            responder_model,
        },
        CertStatus::Unknown(_) => Answer::Stale,
        CertStatus::Revoked(info) => Answer::Revoked {
            time: generalized(&info.revocation_time.0),
            reason: info.revocation_reason.map(reason_name),
            this_update,
            next_update,
            produced_at: Some(produced_at),
            responder_model,
        },
    }
}

/// RFC 6960 section 4.1.1: the `CertID` names the issuer by hashes of its DN
/// and public key, plus the certificate's serial number.
///
/// SHA-1 is accepted **here and only here**. These hashes identify which
/// certificate a response is about; they are not a signature, and RFC 6960
/// makes SHA-1 the default algorithm, so refusing it would make every real
/// OCSP response unusable while defending nothing. A second preimage would
/// only let an attacker point a response at a certificate whose issuer DN and
/// public key both collide, and the response's own signature still has to
/// verify under the pinned allowlist.
fn cert_id_matches(
    cert_id: &x509_ocsp::CertId,
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
) -> bool {
    if cert_id.serial_number.as_bytes()
        != subject.certificate.tbs_certificate.serial_number.as_bytes()
    {
        return false;
    }
    let Some(key) = issuer
        .certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
    else {
        return false;
    };
    let name = subject.issuer_der();
    let Some(name_hash) = digest_by_oid(cert_id.hash_algorithm.oid, &name) else {
        return false;
    };
    let Some(key_hash) = digest_by_oid(cert_id.hash_algorithm.oid, key) else {
        return false;
    };
    name_hash == cert_id.issuer_name_hash.as_bytes()
        && key_hash == cert_id.issuer_key_hash.as_bytes()
}

fn digest_by_oid(oid: ObjectIdentifier, bytes: &[u8]) -> Option<Vec<u8>> {
    match oid {
        OID_SHA1 => Some(Sha1::digest(bytes).to_vec()),
        OID_SHA256 => Some(Sha256::digest(bytes).to_vec()),
        OID_SHA384 => Some(Sha384::digest(bytes).to_vec()),
        OID_SHA512 => Some(Sha512::digest(bytes).to_vec()),
        _ => None,
    }
}

/// Which RFC 6960 model, if any, authorises this response.
///
/// Three models, tried in this order, and the order is the point:
///
/// 1. **Issuer.** The CA that issued the queried certificate signed the
///    response itself. It is the strongest answer available and nothing weaker
///    is looked at once it holds.
/// 2. **Delegated** (section 4.2.2.2). A certificate that same CA issued,
///    naming itself in the `ResponderID`, carrying `id-kp-OCSPSigning` and
///    valid at the time asked about, signed it. The CA's signature over the
///    responder certificate *is* the delegation, so this needs no trust store.
/// 3. **Trusted responder** (section 2.2). The responder is one the relying
///    party trusts directly: it carries `id-kp-OCSPSigning` and its path
///    validates to a configured trust anchor at `producedAt`, even though the
///    queried certificate's issuer never delegated to it.
///
/// The third model is not a relaxation of the first two, it is the third thing
/// RFC 6960 has always allowed, and real hierarchies need it: a national CA
/// operator commonly runs **one** responder for every CA it operates, issued
/// by a sibling CA rather than by whichever CA issued the certificate being
/// asked about. A verifier implementing only the delegation model rejects
/// every one of those answers as unauthorised, which is what openSzigno did
/// before M3 and is why 50 real responses came back
/// `revocation_data_invalid`.
///
/// What keeps it honest is where the authority comes from. A delegated
/// responder is vouched for by the issuing CA; a trusted responder is vouched
/// for by the **caller's own trust store or trusted list**, through a full
/// path validation with `id-kp-OCSPSigning` required on the leaf. A responder
/// that reaches no configured anchor authorises nothing, so this can never
/// admit a response the operator did not already choose to trust the signer
/// of. It is tried last so that a CA's own word always wins over the caller's
/// configuration where both are available.
fn responder_authorised(
    basic: &BasicOcspResponse,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    produced_at: UnixTime,
    time: UnixTime,
    limits: &VerifyLimits,
) -> Option<ResponderModel> {
    let Ok(message) = basic.tbs_response_data.to_der() else {
        return None;
    };
    let signature = basic.signature.as_bytes()?;
    let algorithm = basic.signature_algorithm.oid;
    let responder = &basic.tbs_response_data.responder_id;

    // 1. The issuing CA answered for itself.
    if responder_names(responder, issuer)
        && verify_der_signature(&issuer.certificate, algorithm, &message, signature).is_ok()
    {
        return Some(ResponderModel::Issuer);
    }

    // The certificates the response carries, plus everything else the run has
    // to hand. A central responder's own certificate usually travels with the
    // response; its issuing CA usually does not, and comes from the dossier's
    // `CertificateValues` or the trust store instead.
    let mut offered: Vec<ParsedCertificate> = Vec::new();
    for certificate in basic.certs.as_deref().unwrap_or_default() {
        if let Ok(der) = certificate.to_der()
            && let Some(parsed) =
                ParsedCertificate::from_der(&der, crate::certs::CertificateSource::OcspResponse)
        {
            offered.push(parsed);
        }
    }
    let named: Vec<&ParsedCertificate> = offered
        .iter()
        .chain(candidates.iter())
        .filter(|parsed| responder_names(responder, parsed))
        .collect();

    // 2. A responder the issuing CA delegated to.
    for parsed in &named {
        if parsed.has_ocsp_signing_eku()
            && parsed.is_valid_at(time)
            && parsed.issuer_der() == issuer.subject_der()
            && crate::certs::verify_issued_by(parsed, issuer)
            && verify_der_signature(&parsed.certificate, algorithm, &message, signature).is_ok()
        {
            return Some(ResponderModel::Delegated);
        }
    }

    // 3. A responder the caller trusts directly.
    //
    // The path is validated at `producedAt`, which is the instant the
    // responder asserts it made the statement: a responder certificate that
    // had expired by then was not entitled to say anything, and one that
    // expired afterwards said it while it still was. `keyUsage` is enforced by
    // the same path validator that enforces it everywhere else.
    if anchors.is_empty() {
        return None;
    }
    for parsed in &named {
        if !parsed.has_ocsp_signing_eku() {
            continue;
        }
        if verify_der_signature(&parsed.certificate, algorithm, &message, signature).is_err() {
            continue;
        }
        let pool: Vec<ParsedCertificate> = offered
            .iter()
            .chain(candidates.iter())
            .cloned()
            .collect::<Vec<_>>();
        let outcome = crate::certs::validate_path(
            parsed,
            &crate::certs::dedup(pool),
            anchors,
            produced_at,
            limits,
            crate::certs::PathPurpose::OcspSigning,
        );
        if outcome.code == CheckCode::CertPathOk {
            return Some(ResponderModel::Trusted);
        }
    }
    None
}

/// Whether a `ResponderID` names this certificate, by subject name or by the
/// SHA-1 hash of its public key that RFC 6960 prescribes.
fn responder_names(responder: &ResponderId, certificate: &ParsedCertificate) -> bool {
    match responder {
        ResponderId::ByName(name) => name.to_der().unwrap_or_default() == certificate.subject_der(),
        ResponderId::ByKey(hash) => certificate
            .certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .is_some_and(|key| Sha1::digest(key).to_vec() == hash.as_bytes()),
    }
}

/// The RFC 6960 `CertID` naming one certificate, as DER.
///
/// It is what a request is *about*, and it is exposed because deduplication
/// needs it: two certificates issued by the same CA share one responder URL,
/// and a fetcher that deduplicated by URL alone would ask about the first and
/// silently never ask about the second. The URL says where to ask; this says
/// what was asked. It is also what names a cached response on disk, so two
/// answers from one responder cannot be mistaken for one another.
pub fn ocsp_cert_id(subject: &ParsedCertificate, issuer: &ParsedCertificate) -> Option<Vec<u8>> {
    cert_id(subject, issuer)?.to_der().ok()
}

fn cert_id(subject: &ParsedCertificate, issuer: &ParsedCertificate) -> Option<x509_ocsp::CertId> {
    use der::asn1::OctetString;

    let key = issuer
        .certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()?;
    Some(x509_ocsp::CertId {
        hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: OID_SHA256,
            parameters: Some(der::Any::null()),
        },
        issuer_name_hash: OctetString::new(Sha256::digest(subject.issuer_der()).to_vec()).ok()?,
        issuer_key_hash: OctetString::new(Sha256::digest(key).to_vec()).ok()?,
        serial_number: subject.certificate.tbs_certificate.serial_number.clone(),
    })
}

/// Build an RFC 6960 `OCSPRequest` asking about one certificate.
///
/// This is DER assembly, not networking: the crate still opens no socket, and
/// what the CLI does with the bytes is the CLI's business. Building the
/// request here keeps every line of OCSP ASN.1 this project speaks in one
/// file, next to the code that will have to make sense of the answer.
///
/// The `certID` is computed with **SHA-256**, which is inside the pinned
/// allowlist. RFC 6960 makes SHA-1 the default and a responder is entitled to
/// answer only about the `certID` it was asked about, so a responder that
/// insists on SHA-1 simply yields no usable answer and the certificate stays
/// `revocation_status_unknown` — the same place it was before anything was
/// fetched. Asking with SHA-1 to raise the hit rate would mean this build
/// *generating* a legacy digest, which is a different thing from accepting one
/// in an archived response it did not create.
///
/// No nonce is sent. A nonce defends a live request against replay, and the
/// response is going to be handed to a verifier that deliberately ignores
/// nonces because it must also read responses archived years ago; adding one
/// would defend nothing and would make some responders refuse outright.
pub fn ocsp_request(subject: &ParsedCertificate, issuer: &ParsedCertificate) -> Option<Vec<u8>> {
    let cert_id = cert_id(subject, issuer)?;
    let request = x509_ocsp::OcspRequest {
        tbs_request: x509_ocsp::TbsRequest {
            version: x509_ocsp::Version::V1,
            requestor_name: None,
            request_list: vec![x509_ocsp::Request {
                req_cert: cert_id,
                single_request_extensions: None,
            }],
            request_extensions: None,
        },
        optional_signature: None,
    };
    request.to_der().ok()
}
