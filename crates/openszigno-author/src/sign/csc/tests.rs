//! Unit tests for the CSC request builders, the response readers and the
//! algorithm mapping.
//!
//! The three `info` bodies below are the ones `docs/remote-signing.md` section
//! 3.5 recorded from live services, trimmed to the fields this client reads.
//! They are here because the whole design branches on them and they change
//! without notice.

use super::*;

/// The EUDI reference QTSP: CSC 2.2, `dtbsr` hashes, `supportsRar`, ECDSA.
const EUDI_INFO: &str = r#"{
  "specs": "2.2.0.0",
  "name": "remote Qualifies Electronic Signature QTSP",
  "authType": ["oauth2code"],
  "methods": ["oauth2/authorize", "credentials/list", "credentials/info",
              "signatures/signHash"],
  "signAlgorithms": {"algos": ["1.2.840.10045.2.1", "1.2.840.10045.4.3.2"],
                     "algoParams": []},
  "supportsRar": true,
  "supportedHashTypes": ["dtbsr"]
}"#;

/// PrimeSign: CSC 2.1.0.1, `dtbsr`, RSASSA-PSS with DER parameters.
const PRIMESIGN_INFO: &str = r#"{
  "specs": "2.1.0.1",
  "name": "primesign MOBILE",
  "authType": ["oauth2code"],
  "methods": ["credentials/list", "credentials/info", "signatures/signHash"],
  "signAlgorithms": {
    "algos": ["1.2.840.113549.1.1.10", "1.2.840.10045.4.3.2"],
    "algoParams": ["MCEwCwYJYIZIAWUDBAIBoRgwFgYJKoZIhvcNAQEIMAkGBSsOAwIaBQA=", ""]
  },
  "supportsRar": true,
  "supportedHashTypes": ["dtbsr"]
}"#;

/// Cleverbase: CSC 2.2, the hash type given as an OID, no RAR.
const CLEVERBASE_INFO: &str = r#"{
  "specs": "2.2.0.0",
  "name": "Cleverbase CSC V2 Testbed",
  "authType": ["oauth2code"],
  "methods": ["oauth2/authorize", "oauth2/pushed_authorize", "credentials/list",
              "credentials/info", "signatures/signHash"],
  "signAlgorithms": {"algos": ["1.2.840.10045.4.3.2"], "algoParams": []},
  "supportsRar": false,
  "supportedHashTypes": ["2.16.840.1.101.3.4.2.1"]
}"#;

fn credential(algorithms: &[&str], mode: &str) -> CredentialInfo {
    CredentialInfo {
        credential_id: "cred-1a2b3c".to_owned(),
        auth_mode: if mode == "explicit" {
            AuthMode::Explicit
        } else {
            AuthMode::OAuth2
        },
        certificate: vec![0x30],
        chain: Vec::new(),
        key_algorithms: algorithms.iter().map(|value| (*value).to_owned()).collect(),
        scal: Some("2".to_owned()),
        multisign: Some(1),
    }
}

#[test]
fn the_three_surveyed_services_are_all_accepted_and_keep_what_they_said() {
    let eudi = parse_info(EUDI_INFO.as_bytes()).expect("a CSC 2.2 service");
    assert_eq!(eudi.major(), Some(2));
    assert!(eudi.supports_rar);
    assert_eq!(eudi.supported_hash_types, vec!["dtbsr".to_owned()]);

    let primesign = parse_info(PRIMESIGN_INFO.as_bytes()).expect("a CSC 2.1 service");
    assert_eq!(primesign.specs, "2.1.0.1");
    assert!(primesign.params_for(RSASSA_PSS_OID).is_some());
    // An algorithm with an empty `algoParams` slot has no parameters, not an
    // empty string of them.
    assert_eq!(primesign.params_for(ECDSA_WITH_SHA256_OID), None);

    let cleverbase = parse_info(CLEVERBASE_INFO.as_bytes()).expect("a CSC 2.2 service");
    assert!(!cleverbase.supports_rar);
    // The hash type is an OID here and a keyword there; both say the same
    // thing, and the client has to read both.
    assert!(cleverbase.accepts_digest());
    assert!(
        cleverbase
            .methods
            .iter()
            .any(|m| m == "oauth2/pushed_authorize")
    );
}

#[test]
fn a_v1_service_and_one_that_refuses_digests_are_both_refused() {
    let error = parse_info(br#"{"specs":"1.0.4.0"}"#).expect_err("v1 is not implemented");
    assert_eq!(error.code(), SignErrorCode::CscConfigInvalid);
    let error = parse_info(br#"{"specs":"2.2.0.0","supportedHashTypes":["dtbs"]}"#)
        .expect_err("no digest signing");
    assert_eq!(error.code(), SignErrorCode::CscConfigInvalid);
    let error = parse_info(b"not json").expect_err("not a response");
    assert_eq!(error.code(), SignErrorCode::CscRejected);
    // A service that predates the field signed digests and nothing else.
    assert!(
        parse_info(br#"{"specs":"2.0.0.2"}"#)
            .expect("an early v2 service")
            .accepts_digest()
    );
}

#[test]
fn one_credential_is_taken_and_several_are_never_guessed_between() {
    assert_eq!(
        parse_sole_credential(br#"{"credentialIDs":["cred-1a2b3c"]}"#).expect("exactly one"),
        "cred-1a2b3c"
    );
    let error = parse_sole_credential(br#"{"credentialIDs":[]}"#).expect_err("none at all");
    assert_eq!(error.code(), SignErrorCode::CscCredentialUnusable);
    let error = parse_sole_credential(br#"{"credentialIDs":["a","b"]}"#).expect_err("two");
    assert_eq!(error.code(), SignErrorCode::CscCredentialAmbiguous);
    // The refusal names them, because the user has to pick one.
    assert!(error.message().contains("a, b"));
    assert!(error.message().contains("--csc-credential"));
}

#[test]
fn a_credential_response_yields_the_certificate_the_chain_and_the_mode() {
    let (_, signer) = ec_material();
    let (_, issuer) = ec_material();
    let body = format!(
        r#"{{"key":{{"status":"enabled","algo":["{ECDSA_WITH_SHA256_OID}"]}},
             "cert":{{"status":"valid","certificates":["{}","{}"]}},
             "authMode":"explicit","SCAL":"2","multisign":1}}"#,
        encode_base64(&signer),
        encode_base64(&issuer)
    );
    let info = parse_credential_info("cred-1", body.as_bytes()).expect("a usable credential");
    assert_eq!(info.auth_mode, AuthMode::Explicit);
    // The signer's own certificate first, the rest of the chain behind it:
    // one goes into ds:KeyInfo, the others into xades:CertificateValues.
    assert_eq!(info.certificate, signer);
    assert_eq!(info.chain, vec![issuer]);
    assert_eq!(info.scal.as_deref(), Some("2"));
    assert_eq!(info.multisign, Some(1));

    // The nested `auth` object says the same thing as `authMode`, and a
    // credential that says neither is treated as the interactive case.
    let body = format!(
        r#"{{"key":{{"algo":["{ECDSA_WITH_SHA256_OID}"]}},
             "cert":{{"certificates":["{}"]}},"auth":{{"mode":"explicit"}}}}"#,
        encode_base64(&signer)
    );
    assert_eq!(
        parse_credential_info("cred-1", body.as_bytes())
            .expect("a usable credential")
            .auth_mode,
        AuthMode::Explicit
    );
    let body = format!(
        r#"{{"key":{{"algo":["{ECDSA_WITH_SHA256_OID}"]}},"cert":{{"certificates":["{}"]}}}}"#,
        encode_base64(&signer)
    );
    assert_eq!(
        parse_credential_info("cred-1", body.as_bytes())
            .expect("a usable credential")
            .auth_mode,
        AuthMode::OAuth2
    );
}

#[test]
fn a_credential_that_cannot_sign_is_refused_with_one_code() {
    for body in [
        // A disabled key, a certificate the service itself calls invalid, no
        // certificate at all, no algorithm at all, and two certificates that
        // are not certificates.
        r#"{"key":{"status":"disabled","algo":["1.2.840.10045.4.3.2"]},"cert":{"certificates":["MAA="]}}"#,
        r#"{"key":{"algo":["1.2.840.10045.4.3.2"]},"cert":{"status":"expired","certificates":["MAA="]}}"#,
        r#"{"key":{"algo":["1.2.840.10045.4.3.2"]},"cert":{"certificates":[]}}"#,
        r#"{"key":{"algo":["1.2.840.10045.4.3.2"]},"cert":{"certificates":["not base64!!"]}}"#,
        r#"{"key":{"algo":["1.2.840.10045.4.3.2"]},"cert":{"certificates":["AAAA"]}}"#,
    ] {
        let error = parse_credential_info("cred-1", body.as_bytes()).expect_err("unusable");
        assert_eq!(error.code(), SignErrorCode::CscCredentialUnusable, "{body}");
    }
    // A credential with a real certificate but no algorithm is unusable too:
    // nothing says how to sign with it.
    let (_, signer) = ec_material();
    let body = format!(
        r#"{{"key":{{"algo":[]}},"cert":{{"certificates":["{}"]}}}}"#,
        encode_base64(&signer)
    );
    assert_eq!(
        parse_credential_info("cred-1", body.as_bytes())
            .expect_err("no algorithm")
            .code(),
        SignErrorCode::CscCredentialUnusable
    );
}

#[test]
fn every_request_body_carries_what_the_protocol_binds_to() {
    assert_eq!(info_request(), r#"{"lang":"en"}"#);
    assert!(credentials_list_request().contains("onlyValid"));

    let body = credential_info_request("cred-1a2b3c");
    assert!(body.contains(r#""credentialID":"cred-1a2b3c""#));
    // The chain is asked for because it becomes xades:CertificateValues.
    assert!(body.contains(r#""certificates":"chain""#));
    assert!(body.contains(r#""certInfo":true"#));

    let hashes = vec![encode_base64(&[1_u8; 32])];
    let body = authorize_request("cred-1a2b3c", &hashes, Some("1234"), None);
    // The real hash and the real count: a SAD bound to neither authorises
    // signing anything for its lifetime.
    assert!(body.contains(r#""numSignatures":1"#));
    assert!(body.contains(&hashes[0]));
    assert!(body.contains(&format!(r#""hashAlgorithmOID":"{SHA256_OID}""#)));
    assert!(body.contains(r#""PIN":"1234""#));
    assert!(!body.contains("OTP"));
    assert!(!authorize_request("c", &hashes, None, None).contains("PIN"));
    assert!(authorize_request("c", &hashes, None, Some("738291")).contains(r#""OTP":"738291""#));

    let algorithm = ChosenAlgorithm {
        algorithm: SignatureAlgorithm::RsaPssSha256,
        sign_algo: RSASSA_PSS_OID.to_owned(),
        sign_algo_params: Some("MCE=".to_owned()),
    };
    let body = sign_hash_request("cred-1a2b3c", "sad-value", &hashes, &algorithm);
    assert!(body.contains(r#""SAD":"sad-value""#));
    assert!(body.contains(&format!(r#""signAlgo":"{RSASSA_PSS_OID}""#)));
    assert!(body.contains(r#""signAlgoParams":"MCE=""#));
    assert!(body.contains(r#""operationMode":"S""#));
    let plain = ChosenAlgorithm {
        algorithm: SignatureAlgorithm::RsaSha256,
        sign_algo: SHA256_WITH_RSA_OID.to_owned(),
        sign_algo_params: None,
    };
    assert!(!sign_hash_request("c", "s", &hashes, &plain).contains("signAlgoParams"));
}

#[test]
fn an_authorisation_without_a_sad_is_a_rejection() {
    assert_eq!(
        parse_authorize(br#"{"SAD":"_TiHRG-bAH3XlFQZ","expiresIn":300}"#).expect("a SAD"),
        "_TiHRG-bAH3XlFQZ"
    );
    for body in [&br#"{"expiresIn":300}"#[..], br#"{"SAD":""}"#, b"not json"] {
        assert_eq!(
            parse_authorize(body).expect_err("no SAD").code(),
            SignErrorCode::CscRejected
        );
    }
}

#[test]
fn a_signature_comes_back_in_the_encoding_xmldsig_writes() {
    let raw = vec![7_u8; 64];
    let body = format!(r#"{{"signatures":["{}"]}}"#, encode_base64(&raw));
    // Raw r||s passes through untouched.
    assert_eq!(
        parse_sign_hash(body.as_bytes(), SignatureAlgorithm::EcdsaP256Sha256).expect("raw"),
        raw
    );
    // An RSA signature is whatever length the modulus is.
    let rsa = vec![9_u8; 256];
    let body = format!(r#"{{"signatures":["{}"]}}"#, encode_base64(&rsa));
    assert_eq!(
        parse_sign_hash(body.as_bytes(), SignatureAlgorithm::RsaSha256).expect("rsa"),
        rsa
    );
    // DER is converted, because services disagree about which one they send.
    let signing = p256::ecdsa::SigningKey::random(&mut rsa::rand_core::OsRng);
    let signature: p256::ecdsa::Signature = {
        use p256::ecdsa::signature::Signer as _;
        signing.sign(b"octets")
    };
    let der = signature.to_der();
    let body = format!(r#"{{"signatures":["{}"]}}"#, encode_base64(der.as_bytes()));
    assert_eq!(
        parse_sign_hash(body.as_bytes(), SignatureAlgorithm::EcdsaP256Sha256).expect("der"),
        signature.to_bytes().to_vec()
    );
}

#[test]
fn a_signature_list_that_is_not_one_signature_is_a_rejection() {
    for body in [
        &br#"{"signatures":[]}"#[..],
        br#"{"signatures":["AAAA","BBBB"]}"#,
        br#"{"signatures":["not base64!!"]}"#,
        b"not json",
    ] {
        assert_eq!(
            parse_sign_hash(body, SignatureAlgorithm::RsaSha256)
                .expect_err("not one signature")
                .code(),
            SignErrorCode::CscRejected
        );
    }
    // Neither DER nor 64 bytes is refused rather than written.
    assert_eq!(
        parse_sign_hash(
            br#"{"signatures":["AAAA"]}"#,
            SignatureAlgorithm::EcdsaP256Sha256
        )
        .expect_err("neither encoding")
        .code(),
        SignErrorCode::CscRejected
    );
}

#[test]
fn the_algorithm_comes_from_the_credential_and_a_scheme_beats_a_key() {
    let eudi = parse_info(EUDI_INFO.as_bytes()).expect("info");
    let chosen = choose_algorithm(&credential(&[ECDSA_WITH_SHA256_OID], "oauth2"), &eudi)
        .expect("ECDSA is offered");
    assert_eq!(chosen.algorithm, SignatureAlgorithm::EcdsaP256Sha256);
    assert_eq!(chosen.sign_algo, ECDSA_WITH_SHA256_OID);
    assert_eq!(chosen.sign_algo_params, None);

    // A bare key OID names the scheme this build writes for that key type.
    let chosen = choose_algorithm(&credential(&[EC_PUBLIC_KEY_OID], "oauth2"), &eudi)
        .expect("the key algorithm is enough");
    assert_eq!(chosen.sign_algo, ECDSA_WITH_SHA256_OID);
    let chosen = choose_algorithm(&credential(&[RSA_ENCRYPTION_OID], "oauth2"), &eudi)
        .expect("rsaEncryption is enough");
    assert_eq!(chosen.algorithm, SignatureAlgorithm::RsaSha256);
    assert_eq!(chosen.sign_algo, RSA_ENCRYPTION_OID);

    // PKCS#1 v1.5 wins over PSS whenever both are on offer.
    let primesign = parse_info(PRIMESIGN_INFO.as_bytes()).expect("info");
    let chosen = choose_algorithm(
        &credential(&[RSASSA_PSS_OID, SHA256_WITH_RSA_OID], "explicit"),
        &primesign,
    )
    .expect("both are offered");
    assert_eq!(chosen.algorithm, SignatureAlgorithm::RsaSha256);

    // PSS alone is chosen, with the parameters the service published.
    let chosen = choose_algorithm(&credential(&[RSASSA_PSS_OID], "explicit"), &primesign)
        .expect("PSS is all there is");
    assert_eq!(chosen.algorithm, SignatureAlgorithm::RsaPssSha256);
    assert!(chosen.sign_algo_params.is_some());
}

#[test]
fn an_unusable_or_unparameterised_algorithm_is_refused() {
    let eudi = parse_info(EUDI_INFO.as_bytes()).expect("info");
    // PSS without `signAlgoParams` would mean guessing the salt length.
    let error = choose_algorithm(&credential(&[RSASSA_PSS_OID], "explicit"), &eudi)
        .expect_err("no parameters");
    assert_eq!(error.code(), SignErrorCode::CscCredentialUnusable);
    let error = choose_algorithm(&credential(&["1.2.840.113549.1.1.5"], "explicit"), &eudi)
        .expect_err("RSA-SHA1 is not written by this build");
    assert_eq!(error.code(), SignErrorCode::CscCredentialUnusable);
    assert!(error.message().contains("1.2.840.113549.1.1.5"));
}

/// A P-256 key and a self-signed certificate for it, minted here.
fn ec_material() -> (p256::ecdsa::SigningKey, Vec<u8>) {
    use p256::pkcs8::DecodePrivateKey as _;

    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("a P-256 key is generated");
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("no SAN is valid");
    let certificate = params.self_signed(&pair).expect("self-signing succeeds");
    let key = p256::ecdsa::SigningKey::from_slice(
        &p256::SecretKey::from_pkcs8_der(&pair.serialize_der())
            .expect("the key decodes")
            .to_bytes(),
    )
    .expect("the key is usable");
    (key, certificate.der().to_vec())
}

#[test]
fn a_returned_signature_is_checked_against_the_returned_certificate() {
    use sha2::Digest as _;

    let (key, certificate) = ec_material();
    let digest = sha2::Sha256::digest(b"canonicalized SignedInfo").to_vec();
    let signature: p256::ecdsa::Signature = {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        key.sign_prehash(&digest).expect("prehash signing works")
    };
    verify_prehash(
        &certificate,
        SignatureAlgorithm::EcdsaP256Sha256,
        &digest,
        &signature.to_bytes(),
    )
    .expect("the service signed the digest it was handed");

    // A signature over another digest is exactly the failure this check
    // exists for: it is well formed and it covers the wrong bytes.
    let other = sha2::Sha256::digest(b"something else").to_vec();
    let error = verify_prehash(
        &certificate,
        SignatureAlgorithm::EcdsaP256Sha256,
        &other,
        &signature.to_bytes(),
    )
    .expect_err("the wrong bytes");
    assert_eq!(error.code(), SignErrorCode::CscSignatureInvalid);
    assert!(error.message().contains("nothing was written"));

    // Nonsense in place of a signature is the same refusal, not a panic.
    assert_eq!(
        verify_prehash(
            &certificate,
            SignatureAlgorithm::EcdsaP256Sha256,
            &digest,
            b"short"
        )
        .expect_err("not a signature")
        .code(),
        SignErrorCode::CscSignatureInvalid
    );
    // An unreadable certificate is a credential problem, not a signature one.
    assert_eq!(
        verify_prehash(
            b"not a certificate",
            SignatureAlgorithm::EcdsaP256Sha256,
            &digest,
            &signature.to_bytes()
        )
        .expect_err("not a certificate")
        .code(),
        SignErrorCode::CscCredentialUnusable
    );
}

#[test]
fn an_rsa_signature_is_checked_the_same_way() {
    use rsa::pkcs8::EncodePublicKey as _;
    use rsa::signature::hazmat::PrehashSigner as _;
    use sha2::Digest as _;

    // A small key: this test checks the wiring, not the strength, and key
    // generation is the slow part of it.
    let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).expect("a key");
    let public = rsa::RsaPublicKey::from(&private);
    let spki = public.to_public_key_der().expect("SPKI encodes");
    // A certificate is not minted here: `verify_prehash` needs one, so the
    // test drives the code through a certificate built around this key.
    let certificate = certificate_around(spki.as_bytes());
    let digest = sha2::Sha256::digest(b"canonicalized SignedInfo").to_vec();
    let signature = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private)
        .sign_prehash(&digest)
        .expect("prehash signing works");
    use rsa::signature::SignatureEncoding as _;
    verify_prehash(
        &certificate,
        SignatureAlgorithm::RsaSha256,
        &digest,
        &signature.to_vec(),
    )
    .expect("the digest was signed");
    assert_eq!(
        verify_prehash(
            &certificate,
            SignatureAlgorithm::RsaSha256,
            &sha2::Sha256::digest(b"other"),
            &signature.to_vec()
        )
        .expect_err("the wrong bytes")
        .code(),
        SignErrorCode::CscSignatureInvalid
    );
}

/// A certificate carrying `spki` as its subject public key.
///
/// The signature on it is meaningless and never checked: `verify_prehash`
/// reads the public key out of a certificate and nothing else.
fn certificate_around(spki: &[u8]) -> Vec<u8> {
    let template = {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("a P-256 key is generated");
        let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("no SAN is valid");
        params
            .self_signed(&pair)
            .expect("self-signing succeeds")
            .der()
            .to_vec()
    };
    let mut certificate = Certificate::from_der(&template).expect("the template decodes");
    certificate.tbs_certificate.subject_public_key_info =
        x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(spki).expect("the SPKI decodes");
    certificate.to_der().expect("the certificate encodes")
}
