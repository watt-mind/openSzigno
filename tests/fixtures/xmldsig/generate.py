#!/usr/bin/env python3
"""Generate the independent XMLDSig vector in this directory.

Nothing here uses openSzigno. The certificates, the RSA signature, and the
SHA-256 digests are produced by OpenSSL and by Python's hashlib; the canonical
octets they are computed over are written out by hand, following the rules of
Canonical XML 1.0 and Exclusive XML Canonicalization 1.0 rather than by
running a canonicalizer. The point of the fixture is that openSzigno's own
canonicalizer must reproduce those octets: if it drifts, the committed digests
and signature stop verifying.

Every referenced element below is written so that its exclusive-C14N form is
the element's own source text: the namespace prefix it uses is declared on the
element itself, attributes are already in canonical order (unprefixed
attributes sorted by name), every element has an explicit end tag, there are
no comments or processing instructions, the text is ASCII, and line endings
are LF.

Usage: python3 generate.py    (rerunning replaces the key, so the committed
signature changes; the committed files are the ones the tests use)
"""

import base64
import hashlib
import subprocess
import textwrap
from pathlib import Path

HERE = Path(__file__).parent
ES = "https://www.microsec.hu/ds/e-szigno30#"
DS = "http://www.w3.org/2000/09/xmldsig#"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"


def openssl(*args, **kwargs):
    return subprocess.run(["openssl", *args], check=True, **kwargs)


def make_pki():
    """A synthetic root CA and one signing certificate, both from OpenSSL."""
    openssl("genrsa", "-out", str(HERE / "root.key"), "2048", stderr=subprocess.DEVNULL)
    openssl("genrsa", "-out", str(HERE / "signer.key"), "2048", stderr=subprocess.DEVNULL)
    (HERE / "root.cnf").write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        "[dn]\nCN=openSzigno OpenSSL Vector Root\nO=openSzigno synthetic test PKI\nC=HU\n"
        "[v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
    )
    (HERE / "signer.cnf").write_text(
        "[req]\ndistinguished_name=dn\nprompt=no\n"
        "[dn]\nCN=openSzigno OpenSSL Vector Signer\nO=openSzigno synthetic test PKI\nC=HU\n"
        "[v3]\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,nonRepudiation\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
    )
    openssl(
        "req", "-x509", "-new", "-key", str(HERE / "root.key"), "-sha256",
        "-days", "7300", "-config", str(HERE / "root.cnf"),
        "-out", str(HERE / "root.pem"), stderr=subprocess.DEVNULL,
    )
    openssl(
        "req", "-new", "-key", str(HERE / "signer.key"), "-config",
        str(HERE / "signer.cnf"), "-out", str(HERE / "signer.csr"),
        stderr=subprocess.DEVNULL,
    )
    openssl(
        "x509", "-req", "-in", str(HERE / "signer.csr"), "-CA", str(HERE / "root.pem"),
        "-CAkey", str(HERE / "root.key"), "-set_serial", "4097", "-days", "7300",
        "-sha256", "-extfile", str(HERE / "signer.cnf"), "-extensions", "v3",
        "-out", str(HERE / "signer.pem"), stderr=subprocess.DEVNULL,
    )
    for scratch in ("root.cnf", "signer.cnf", "signer.csr"):
        (HERE / scratch).unlink()


def der_base64(pem_path):
    """The certificate as the Base64 of its DER, which is what ds:KeyInfo holds."""
    body = "".join(
        line for line in pem_path.read_text().splitlines()
        if not line.startswith("-----")
    )
    return body


def digest(octets):
    return base64.b64encode(hashlib.sha256(octets.encode("utf-8")).digest()).decode()


def main():
    make_pki()

    # --- the three referenced elements, written in their canonical form ------
    profile = (
        f'<es:DocumentProfile xmlns:es="{ES}" Id="prof0" OBJREF="obj0">'
        "<es:Title>openSzigno OpenSSL vector</es:Title>"
        "<es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>"
        '<es:Format><es:MIME-Type extension="txt" subtype="plain" type="text"></es:MIME-Type>'
        "</es:Format>"
        '<es:SourceSize sizeUnit="B" sizeValue="5"></es:SourceSize>'
        '<es:BaseTransform><es:Transform Algorithm="base64"></es:Transform></es:BaseTransform>'
        "</es:DocumentProfile>"
    )
    payload = f'<ds:Object xmlns:ds="{DS}" Id="obj0">aGVsbG8=</ds:Object>'
    signature_object = (
        f'<ds:Object xmlns:ds="{DS}" Id="sigobj0">'
        f'<es:SignatureProfile xmlns:es="{ES}" Id="sigprof0">'
        "<es:SignerName>openSzigno OpenSSL Vector Signer</es:SignerName>"
        "<es:Type>signature</es:Type>"
        "<es:Generator>openssl and generate.py</es:Generator>"
        "</es:SignatureProfile></ds:Object>"
    )

    def reference(uri, value):
        return (
            f'<ds:Reference URI="{uri}"><ds:Transforms>'
            f'<ds:Transform Algorithm="{EXC}"></ds:Transform></ds:Transforms>'
            f'<ds:DigestMethod Algorithm="{SHA256}"></ds:DigestMethod>'
            f"<ds:DigestValue>{value}</ds:DigestValue></ds:Reference>"
        )

    signed_info = (
        f'<ds:SignedInfo xmlns:ds="{DS}">'
        f'<ds:CanonicalizationMethod Algorithm="{EXC}"></ds:CanonicalizationMethod>'
        f'<ds:SignatureMethod Algorithm="{RSA_SHA256}"></ds:SignatureMethod>'
        + reference("#obj0", digest(payload))
        + reference("#prof0", digest(profile))
        + reference("#sigobj0", digest(signature_object))
        + "</ds:SignedInfo>"
    )

    # --- OpenSSL signs the canonical ds:SignedInfo octets --------------------
    (HERE / "signedinfo.canonical").write_text(signed_info)
    openssl(
        "dgst", "-sha256", "-sign", str(HERE / "signer.key"),
        "-out", str(HERE / "signedinfo.sig"), str(HERE / "signedinfo.canonical"),
    )
    signature_value = base64.b64encode((HERE / "signedinfo.sig").read_bytes()).decode()
    (HERE / "signedinfo.sig").unlink()

    document = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<es:Dossier xmlns:es="{ES}" xmlns:ds="{DS}">'
        '<es:DossierProfile Id="dossier-profile" OBJREF="documents">'
        "<es:Title>openSzigno OpenSSL vector</es:Title>"
        "<es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>"
        "</es:DossierProfile>"
        '<es:Documents Id="documents"><es:Document>'
        + profile
        + payload
        + '<ds:Signature Id="sig0">'
        + signed_info
        + f"<ds:SignatureValue>{signature_value}</ds:SignatureValue>"
        + f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{der_base64(HERE / "signer.pem")}'
        "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
        + signature_object
        + "</ds:Signature></es:Document></es:Documents></es:Dossier>\n"
    )
    (HERE / "openssl-rsa-sha256.es3").write_text(document)
    print("wrote openssl-rsa-sha256.es3")
    print(textwrap.shorten("signature: " + signature_value, 70))


if __name__ == "__main__":
    main()
