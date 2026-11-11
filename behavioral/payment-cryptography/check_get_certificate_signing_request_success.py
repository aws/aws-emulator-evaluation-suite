"""get-certificate-signing-request-success."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-certificate-signing-request-success"
GROUP = "data-plane"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCertificateSigningRequest on an RSA_2048 signing key returns a PKCS#10 CSR with a valid
    signature, the requested subject and a 2048-bit public key that is the same key
    GetPublicKeyCertificate's certificate embeds."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    pc = ctx.client("payment-cryptography")
    key_attributes = {
        "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
        "KeyClass": "ASYMMETRIC_KEY_PAIR",
        "KeyAlgorithm": "RSA_2048",
        "KeyModesOfUse": {"Sign": True},
    }
    key = pc.create_key(KeyAttributes=key_attributes, Exportable=True)["Key"]
    arn = key["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))

    subject = {
        "CommonName": "sim2real.test",
        "Country": "US",
        "Organization": "Sim2Real",
    }
    resp = pc.get_certificate_signing_request(
        KeyIdentifier=arn,
        SigningAlgorithm="SHA256",
        CertificateSubject=subject,
    )
    csr_pem = _decode_pem(resp["CertificateSigningRequest"])
    assert "-----BEGIN CERTIFICATE REQUEST-----" in csr_pem, (
        f"expected a PEM-encoded CSR, got {csr_pem[:80]!r}"
    )
    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))

    assert csr.is_signature_valid, (
        "CSR signature does not verify against its own embedded public key -- a "
        "placeholder string could never carry a signature that verifies"
    )

    cn = _rdn_value(csr.subject, NameOID.COMMON_NAME)
    org = _rdn_value(csr.subject, NameOID.ORGANIZATION_NAME)
    country = _rdn_value(csr.subject, NameOID.COUNTRY_NAME)
    assert cn == subject["CommonName"], f"expected CSR subject CN={subject['CommonName']!r}, got {cn!r}"
    assert org == subject["Organization"], (
        f"expected CSR subject O={subject['Organization']!r}, got {org!r}"
    )
    assert country == subject["Country"], f"expected CSR subject C={subject['Country']!r}, got {country!r}"

    csr_key = csr.public_key()
    assert csr_key.key_size == 2048, f"expected a 2048-bit RSA public key in the CSR, got {csr_key.key_size}"

    # Independent read at a different operation: the key's own certificate must embed
    # the identical public key the CSR just claimed.
    cert_resp = pc.get_public_key_certificate(KeyIdentifier=arn)
    cert_pem = _decode_pem(cert_resp["KeyCertificate"])
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    assert cert.public_key().public_numbers() == csr_key.public_numbers(), (
        "GetPublicKeyCertificate's embedded public key does not match the public key "
        "GetCertificateSigningRequest just certified for the same KeyIdentifier"
    )


def _rdn_value(name, oid):
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def _decode_pem(value: str) -> str:
    """The API returns the CSR/certificate as PEM text; some accounts/regions instead hand
    back the PEM wrapped in an outer base64 envelope -- decode transparently either way."""
    import base64

    if "-----BEGIN" in value:
        return value
    try:
        return base64.b64decode(value).decode("utf-8", errors="ignore")
    except Exception:
        return value


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
