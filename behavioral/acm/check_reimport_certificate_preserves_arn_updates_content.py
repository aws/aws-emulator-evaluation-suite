"""reimport-certificate-preserves-arn-updates-content."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "reimport-certificate-preserves-arn-updates-content"
GROUP = "lifecycle"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reimporting with the same CertificateArn keeps the ARN but updates SANs and body content."""
    import cryptography  # noqa: F401

    acm = ctx.client("acm")
    domain1 = _domain(ctx, "reimp1")
    domain2 = _domain(ctx, "reimp2")

    leaf1_pem, key_pem, key = _generate_self_signed_cert(domain1, sans=[domain1])
    arn = acm.import_certificate(
        Certificate=leaf1_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    desc1 = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc1["SubjectAlternativeNames"] == [domain1], (
        f"initial import: expected SANs [{domain1}], got {desc1['SubjectAlternativeNames']}"
    )

    # Reimport onto the SAME arn with the SAME key but an extra SAN.
    leaf2_pem, key_pem2, _ = _generate_self_signed_cert(domain1, sans=[domain1, domain2], key=key)
    reimport_resp = acm.import_certificate(
        Certificate=leaf2_pem, PrivateKey=key_pem2, CertificateArn=arn
    )
    assert reimport_resp["CertificateArn"] == arn, "reimport must preserve the certificate ARN"

    desc2 = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc2["DomainName"] == domain1, (
        f"reimport: expected DomainName {domain1!r}, got {desc2['DomainName']!r}"
    )
    assert set(desc2["SubjectAlternativeNames"]) == {domain1, domain2}, desc2["SubjectAlternativeNames"]

    got = acm.get_certificate(CertificateArn=arn)
    returned_pem = got["Certificate"].encode() if isinstance(got["Certificate"], str) else got["Certificate"]
    assert _cert_fingerprint(returned_pem) == _cert_fingerprint(leaf2_pem), (
        "GetCertificate must return the reimported (new) certificate body"
    )
    assert _cert_fingerprint(returned_pem) != _cert_fingerprint(leaf1_pem), (
        "reimported certificate content must have actually changed"
    )


def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    return f"{label}.example.com"


def _generate_self_signed_cert(
    common_name: str,
    sans=None,
    key=None,
    not_after_days: int = 825,
    is_ca: bool = False,
    issuer_key=None,
    issuer_cn: str | None = None,
):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or common_name)])
    signing_key = issuer_key or key
    san_names = [common_name] + [s for s in (sans or []) if s != common_name]
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san_names]), critical=False)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    cert = builder.sign(signing_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem, key


def _cert_fingerprint(pem_bytes: bytes) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    cert = x509.load_pem_x509_certificate(pem_bytes)
    return cert.fingerprint(hashes.SHA256()).hex()


def _safe_delete(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
