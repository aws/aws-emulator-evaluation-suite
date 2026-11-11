"""export-certificate-on-imported-rejected."""
from __future__ import annotations

import base64
import datetime

from behavioral_harness import tags

CHECK = "export-certificate-on-imported-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExportCertificate is refused for an IMPORTED certificate: only PRIVATE (ACM PCA-issued) certs are exportable."""
    import cryptography  # noqa: F401

    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    domain = _domain(ctx, "exportreject")
    cert_pem, key_pem, _key = _generate_self_signed_cert(domain)
    arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc["Type"] == "IMPORTED", f"expected an IMPORTED certificate, got {desc['Type']}"

    passphrase = base64.b64encode(b"Test-Passphrase-1234!").decode()
    try:
        acm.export_certificate(CertificateArn=arn, Passphrase=passphrase)
        raise AssertionError("ExportCertificate must be rejected for an IMPORTED certificate")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ValidationException", code
        message = err.response["Error"].get("Message")
        expected_message = f"Certificate ARN: {arn} is not an export enabled certificate"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
        assert "PrivateKey" not in err.response, "no private key material may be present in the error response"

    # independent read at the destination: the rejected export must not have
    # mutated or removed the certificate it was refused against
    after = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert after["Type"] == "IMPORTED", f"rejected export changed certificate type to {after['Type']}"
    assert after["Status"] == "ISSUED", f"rejected export changed certificate status to {after['Status']}"


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
