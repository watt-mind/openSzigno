//! A synthetic PKI: RSA, ECDSA (P-256/P-384), and Ed25519 test keys, and the
//! certificates and certificate extensions built from them.
//!
//! Every byte here is generated. Nothing is derived from a real dossier.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, NameConstraints, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256,
    SubjectPublicKeyInfo,
};

/// A signing key in both the shapes the helper needs: `rcgen`'s, for issuing
/// certificates, and the RustCrypto one, for signing `ds:SignedInfo`.
pub enum SigningKey {
    Rsa(Box<rsa::RsaPrivateKey>),
    EcdsaP256(Box<p256::ecdsa::SigningKey>),
    EcdsaP384(Box<p384::ecdsa::SigningKey>),
    /// A key that can produce a certificate but never a signature, used for the
    /// weak-key cases the `ring` backend refuses to sign with.
    None,
}

pub struct TestKey {
    pub rcgen: Option<KeyPair>,
    pub signing: SigningKey,
    pub spki_der: Vec<u8>,
}

pub fn rsa_key(pkcs8_base64: &str) -> TestKey {
    let der = decode_key(pkcs8_base64);
    let rcgen = KeyPair::from_pkcs8_der_and_sign_algo(&der.clone().into(), &PKCS_RSA_SHA256).ok();
    let signing = {
        use rsa::pkcs8::DecodePrivateKey as _;
        rsa::RsaPrivateKey::from_pkcs8_der(&der).expect("the embedded RSA key parses")
    };
    let spki_der = {
        use rsa::pkcs8::EncodePublicKey as _;
        rsa::RsaPublicKey::from(&signing)
            .to_public_key_der()
            .expect("the RSA public key encodes")
            .as_bytes()
            .to_vec()
    };
    TestKey {
        rcgen,
        signing: SigningKey::Rsa(Box::new(signing)),
        spki_der,
    }
}

/// A P-384 key derived from a fixed scalar.
pub fn ecdsa_p384_key(seed: u8) -> TestKey {
    use p384::pkcs8::EncodePrivateKey as _;
    let mut scalar = [1u8; 48];
    scalar[47] = seed;
    let secret = p384::SecretKey::from_slice(&scalar).expect("the fixed scalar is in range");
    let pkcs8 = secret.to_pkcs8_der().expect("the P-384 key encodes");
    let rcgen = KeyPair::from_pkcs8_der_and_sign_algo(
        &pkcs8.as_bytes().into(),
        &rcgen::PKCS_ECDSA_P384_SHA384,
    )
    .ok();
    TestKey {
        rcgen,
        signing: SigningKey::EcdsaP384(Box::new(p384::ecdsa::SigningKey::from(&secret))),
        spki_der: Vec::new(),
    }
}

/// An Ed25519 key, whose signature algorithm this tool deliberately does not
/// implement, used to check that an unsupported key type is refused.
pub fn ed25519_key() -> TestKey {
    TestKey {
        rcgen: KeyPair::generate_for(&rcgen::PKCS_ED25519).ok(),
        signing: SigningKey::None,
        spki_der: Vec::new(),
    }
}

/// A P-256 key derived from a fixed scalar, so the suite stays deterministic.
pub fn ecdsa_key(seed: u8) -> TestKey {
    use p256::pkcs8::EncodePrivateKey as _;
    let mut scalar = [1u8; 32];
    scalar[31] = seed;
    let secret = p256::SecretKey::from_slice(&scalar).expect("the fixed scalar is in range");
    let pkcs8 = secret.to_pkcs8_der().expect("the P-256 key encodes");
    let rcgen =
        KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8.as_bytes().into(), &PKCS_ECDSA_P256_SHA256)
            .ok();
    TestKey {
        rcgen,
        signing: SigningKey::EcdsaP256(Box::new(p256::ecdsa::SigningKey::from(&secret))),
        spki_der: Vec::new(),
    }
}

fn decode_key(text: &str) -> Vec<u8> {
    BASE64
        .decode(
            text.chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>(),
        )
        .expect("the embedded key is Base64")
}

/// How one certificate should look.
pub struct CertSpec<'a> {
    pub common_name: &'a str,
    pub not_before: (i32, u8, u8),
    pub not_after: (i32, u8, u8),
    pub is_ca: IsCa,
    pub key_usages: Vec<KeyUsagePurpose>,
    pub name_constraints: Option<NameConstraints>,
    /// Extra extensions, used to plant an unrecognised critical extension.
    pub custom_extensions: Vec<rcgen::CustomExtension>,
    /// Subject alternative names, against which a CA's name constraints for
    /// dNSName, rfc822Name, and URI subtrees are checked.
    pub subject_alt_names: Vec<rcgen::SanType>,
}

impl<'a> CertSpec<'a> {
    pub fn signer(common_name: &'a str) -> Self {
        Self {
            common_name,
            not_before: (2019, 1, 1),
            not_after: (2039, 1, 1),
            is_ca: IsCa::ExplicitNoCa,
            key_usages: vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::ContentCommitment,
            ],
            name_constraints: None,
            custom_extensions: Vec::new(),
            subject_alt_names: Vec::new(),
        }
    }

    pub fn ca(common_name: &'a str, constraints: BasicConstraints) -> Self {
        Self {
            common_name,
            not_before: (2019, 1, 1),
            not_after: (2039, 1, 1),
            is_ca: IsCa::Ca(constraints),
            key_usages: vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
            name_constraints: None,
            custom_extensions: Vec::new(),
            subject_alt_names: Vec::new(),
        }
    }

    fn params(&self) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("no SAN is valid");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, self.common_name);
        name.push(DnType::OrganizationName, "openSzigno synthetic test PKI");
        name.push(DnType::CountryName, "HU");
        params.distinguished_name = name;
        params.not_before =
            rcgen::date_time_ymd(self.not_before.0, self.not_before.1, self.not_before.2);
        params.not_after =
            rcgen::date_time_ymd(self.not_after.0, self.not_after.1, self.not_after.2);
        params.is_ca = self.is_ca;
        params.key_usages.clone_from(&self.key_usages);
        params.name_constraints.clone_from(&self.name_constraints);
        params.custom_extensions.clone_from(&self.custom_extensions);
        params.subject_alt_names.clone_from(&self.subject_alt_names);
        params.use_authority_key_identifier_extension = true;
        params
    }
}

/// An issued certificate and the parameters it was issued from, so it can act
/// as an issuer in turn.
pub struct Issued {
    pub der: Vec<u8>,
    pub params: CertificateParams,
}

pub fn self_signed(spec: &CertSpec<'_>, key: &TestKey) -> Issued {
    let params = spec.params();
    let pair = key.rcgen.as_ref().expect("this key can issue certificates");
    let certificate = params.self_signed(pair).expect("self-signing succeeds");
    Issued {
        der: certificate.der().to_vec(),
        params,
    }
}

pub fn issued_by(
    spec: &CertSpec<'_>,
    subject_key: &TestKey,
    issuer: &Issued,
    issuer_key: &TestKey,
) -> Issued {
    let params = spec.params();
    let issuer_pair = issuer_key
        .rcgen
        .as_ref()
        .expect("the issuer key can sign certificates");
    let authority = Issuer::from_params(&issuer.params, issuer_pair);
    let certificate = match subject_key.rcgen.as_ref() {
        Some(pair) => params.signed_by(pair, &authority),
        // A key `ring` refuses to load (an RSA-1024 key, say) can still appear
        // as a subject public key: only the issuer has to be able to sign.
        None => {
            let public = SubjectPublicKeyInfo::from_der(&subject_key.spki_der)
                .expect("the subject public key parses");
            params.signed_by(&public, &authority)
        }
    }
    .expect("issuing succeeds");
    Issued {
        der: certificate.der().to_vec(),
        params,
    }
}

/// A hand-encoded `nameConstraints` extension, so a test can express subtree
/// forms `rcgen` cannot build (URI, otherName) and exact IP address/mask
/// pairs.
pub fn name_constraints_extension(
    permitted: Vec<x509_cert::ext::pkix::name::GeneralName>,
    excluded: Vec<x509_cert::ext::pkix::name::GeneralName>,
) -> rcgen::CustomExtension {
    use der::Encode as _;
    use x509_cert::ext::pkix::constraints::name::GeneralSubtree;

    let subtrees = |names: Vec<x509_cert::ext::pkix::name::GeneralName>| {
        if names.is_empty() {
            None
        } else {
            Some(
                names
                    .into_iter()
                    .map(|base| GeneralSubtree {
                        base,
                        minimum: 0,
                        maximum: None,
                    })
                    .collect::<Vec<_>>(),
            )
        }
    };
    let constraints = x509_cert::ext::pkix::NameConstraints {
        permitted_subtrees: subtrees(permitted),
        excluded_subtrees: subtrees(excluded),
    };
    let mut extension = rcgen::CustomExtension::from_oid_content(
        &[2, 5, 29, 30],
        constraints.to_der().expect("the constraints encode"),
    );
    extension.set_criticality(true);
    extension
}

/// A hand-encoded `extendedKeyUsage`, so a test can mark it critical.
pub fn extended_key_usage_extension(oids: &[&str], critical: bool) -> rcgen::CustomExtension {
    use der::Encode as _;
    let usages: Vec<const_oid::ObjectIdentifier> = oids
        .iter()
        .map(|oid| oid.parse().expect("a valid OID"))
        .collect();
    let mut extension = rcgen::CustomExtension::from_oid_content(
        &[2, 5, 29, 37],
        usages.to_der().expect("the usages encode"),
    );
    extension.set_criticality(critical);
    extension
}

/// An extension carrying bytes that are not what its OID says they are.
pub fn malformed_extension(oid: &[u64], critical: bool) -> rcgen::CustomExtension {
    let mut extension = rcgen::CustomExtension::from_oid_content(oid, vec![0x2a, 0x2a, 0x2a]);
    extension.set_criticality(critical);
    extension
}

/// A hand-encoded `qcStatements` extension (RFC 3739 section 3.2.6) asserting
/// the given statement OIDs with no `statementInfo`.
pub fn qc_statements_extension(oids: &[&str]) -> rcgen::CustomExtension {
    use der::Encode as _;
    let statements: Vec<der::Any> = oids
        .iter()
        .map(|oid| {
            let identifier = const_oid::ObjectIdentifier::new_unwrap(oid);
            let inner = identifier.to_der().expect("the OID encodes");
            der::Any::new(der::Tag::Sequence, inner).expect("the statement encodes")
        })
        .collect();
    let encoded = statements.to_der().expect("the statement sequence encodes");
    rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 3], encoded)
}

/// A hand-encoded `cRLDistributionPoints` extension naming one URI, so a
/// partitioned CRL's `issuingDistributionPoint` has something to match.
pub fn crl_distribution_point_extension(uri: &str) -> rcgen::CustomExtension {
    use der::Encode as _;
    let point = x509_cert::ext::pkix::crl::dp::DistributionPoint {
        distribution_point: Some(x509_cert::ext::pkix::name::DistributionPointName::FullName(
            vec![
                x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                    der::asn1::Ia5String::new(uri).expect("the URI encodes"),
                ),
            ],
        )),
        reasons: None,
        crl_issuer: None,
    };
    let encoded = vec![point]
        .to_der()
        .expect("the distribution points encode");
    rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 31], encoded)
}

/// An `authorityInfoAccess` extension naming one OCSP responder, which is
/// where `--online` learns a URL to POST a request to.
pub fn authority_info_access_extension(uri: &str) -> rcgen::CustomExtension {
    use der::Encode as _;
    let description = x509_cert::ext::pkix::AccessDescription {
        access_method: const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1"),
        access_location: x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
            der::asn1::Ia5String::new(uri).expect("the URI encodes"),
        ),
    };
    let encoded = vec![description]
        .to_der()
        .expect("the access descriptions encode");
    rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], encoded)
}
