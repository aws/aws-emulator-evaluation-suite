"""describe-certificate-invalid-arn-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "describe-certificate-invalid-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCertificate rejects a malformed ARN with InvalidArnException, distinct from ResourceNotFoundException."""
    import cryptography  # noqa: F401

    from botocore.exceptions import ClientError

    acm = ctx.client("acm")

    # Positive control: a real, well-formed certificate ARN describes successfully.
    domain = _domain(ctx, "arnformat")
    cert_pem, key_pem, _key = _generate_self_signed_cert(domain)
    arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))
    ok = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert ok["CertificateArn"] == arn, (arn, ok["CertificateArn"])

    # Negative: a value that is NOT ARN-shaped at all is a format-validation failure, not a not-found.
    # Note: a too-short string like "not-an-arn" never reaches the service at all -- botocore's
    # client-side length validation rejects it locally with ParamValidationError, so we use a value
    # that passes local shape/length checks (>=20 chars) but does not match the "arn:...:certificate/..."
    # shape at all. A string that keeps the "arn:...:certificate/<id>" shape but just has a bogus id
    # (e.g. "arn:aws:acm:...:certificate/not-a-valid-certificate-id") is still generically ARN-shaped
    # and real ACM treats it as a well-formed-but-nonexistent ARN, returning ResourceNotFoundException
    # rather than a format-validation error -- so it must not be used to exercise the format-validation
    # path. Real ACM rejects a value that does not even look like an ARN with a generic schema-level
    # ValidationException (a pattern-constraint failure caught before any ARN-parsing/lookup logic
    # runs), not the service-specific InvalidArnException -- which is reserved for values that do
    # parse as an ARN but fail ACM's own further-along ARN validation.
    malformed_arn = "not-a-valid-certificate-arn-value-00000000000000"
    try:
        acm.describe_certificate(CertificateArn=malformed_arn)
        raise AssertionError("DescribeCertificate must reject a malformed ARN")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ValidationException", err.response["Error"]["Code"]
        expected_message = (
            "1 validation error detected: Value of the input at 'certificateArn' failed to satisfy "
            "constraint: Member must satisfy regular expression pattern: "
            r"arn:[\w+=/,.@-]+:acm:[\w+=/,.@-]*:[0-9]+:[\w+=,.@-]+(/[\w+=,.@-]+)*"
        )
        message = err.response["Error"].get("Message")
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # A well-formed but non-existent ARN is a DIFFERENT, distinct error (existence, not format).
    fake_arn = arn[: arn.rindex("/") + 1] + "00000000-0000-0000-0000-000000000000"
    try:
        acm.describe_certificate(CertificateArn=fake_arn)
        raise AssertionError("DescribeCertificate must reject a well-formed but nonexistent ARN")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ResourceNotFoundException", err.response["Error"]["Code"]
        expected_message = f"Could not find certificate {fake_arn}."
        message = err.response["Error"].get("Message")
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


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
