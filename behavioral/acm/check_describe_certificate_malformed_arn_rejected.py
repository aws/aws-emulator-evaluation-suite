"""describe-certificate-malformed-arn-rejected."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-certificate-malformed-arn-rejected"
GROUP = 'error-semantics'
SERVICES = ['acm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCertificate rejects a CertificateArn that violates the ACM ARN pattern with
    ValidationException, not ResourceNotFoundException, while the same call on a real certificate
    succeeds."""
    acm = ctx.client("acm")

    cert_pem, key_pem = _self_signed_cert(ctx)
    arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real-purpose", "Value": "describe-malformed-arn-control"}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))
    control = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert control["CertificateArn"] == arn, control

    bad_arn = "this-is-definitely-not-an-arn"
    code, message = _error(lambda: acm.describe_certificate(CertificateArn=bad_arn))
    assert code == "ValidationException", code
    expected_message = (
        "1 validation error detected: Value of the input at 'certificateArn' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: "
        r"arn:[\w+=/,.@-]+:acm:[\w+=/,.@-]*:[0-9]+:[\w+=,.@-]+(/[\w+=,.@-]+)*"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Run fn, which must be refused; return the (code, message) of the refusal."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _self_signed_cert(ctx):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    domain = ctx.unique_name("acm-malarn-").rstrip("-").lower().replace("_", "-") + ".example.com"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _safe_delete(acm, arn: str) -> None:
    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
