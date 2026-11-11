"""export-certificate-key-matches-imported-cert."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "export-certificate-key-matches-imported-cert"
GROUP = "data-plane"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetCertificate on an imported certificate returns the uploaded public key, while
    ExportCertificate refuses it with ValidationException and the exact message: only
    ACM-issued certificates are exportable."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    acm = ctx.client("acm")
    domain = f"{ctx.unique_name('sim2real-acmimp-').lower()}.test"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    # GetCertificate returns the certificate carrying the uploaded key pair's public key.
    fetched_cert_bytes = acm.get_certificate(CertificateArn=cert_arn)["Certificate"]
    if isinstance(fetched_cert_bytes, str):
        fetched_cert_bytes = fetched_cert_bytes.encode()
    fetched_cert = x509.load_pem_x509_certificate(fetched_cert_bytes)
    assert (
        fetched_cert.public_key().public_numbers() == key.public_key().public_numbers()
    ), "GetCertificate returned a certificate whose public key does not match the imported key pair"

    passphrase = b"sim2real-test-pass-1"
    try:
        acm.export_certificate(CertificateArn=cert_arn, Passphrase=passphrase)
        raise AssertionError(
            "expected ExportCertificate to reject a merely-imported certificate "
            "(export is only valid for ACM-issued private/public certificates), "
            "but it returned a certificate+key bundle"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"expected ValidationException exporting an imported (non-ACM-issued) "
            f"certificate, got {code}"
        )
        message = exc.response["Error"].get("Message")
        expected_message = f"Certificate ARN: {cert_arn} is not an export enabled certificate"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
