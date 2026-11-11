"""import-certificate-issued-immediately."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "import-certificate-issued-immediately"
GROUP = "lifecycle"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Importing a self-signed certificate makes it ISSUED immediately (no domain validation needed)."""
    domain = _domain(ctx, "import")
    cert_pem, key_pem, _key = _generate_self_signed_cert(domain)

    acm = ctx.client("acm")
    arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real-purpose", "Value": "import-certificate-issued-immediately"}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc["Status"] == "ISSUED", desc["Status"]
    assert desc["Type"] == "IMPORTED", desc["Type"]
    assert desc["CertificateKeyPairOrigin"] == "CUSTOMER_PROVIDED", desc.get("CertificateKeyPairOrigin")
    assert desc["DomainName"] == domain, desc["DomainName"]
    # Imported certs need no domain validation: any DomainValidationOptions entries ACM reports for the
    # cert's own domain(s) must already show validation as complete, never a pending/actionable state.
    for option in desc.get("DomainValidationOptions") or []:
        assert option.get("ValidationStatus") in (None, "SUCCESS"), (
            f"imported certs need no domain validation, got {option!r}"
        )
        assert "ResourceRecord" not in option, "an already-issued imported cert must not need a DNS challenge"

    # Delete proves gone and unusable: an independent read returns the specific not-found code, and
    # a mutation on the now-dead id also fails with it.
    acm.delete_certificate(CertificateArn=arn)
    code, message = _error(lambda: acm.describe_certificate(CertificateArn=arn))
    assert code == "ResourceNotFoundException", f"deleted cert still describable, got {code!r}"
    expected_message = f"Could not find certificate {arn}."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )
    code, message = _error(
        lambda: acm.add_tags_to_certificate(CertificateArn=arn, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert code == "ResourceNotFoundException", f"mutation on deleted cert should 404, got {code!r}"
    expected_message = f"Could not find certificate {arn}."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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
