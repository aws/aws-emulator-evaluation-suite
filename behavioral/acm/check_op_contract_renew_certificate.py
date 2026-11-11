"""op-contract-renew-certificate."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "op-contract-renew-certificate"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RenewCertificate refuses a nonexistent ARN with ResourceNotFoundException and an INELIGIBLE
    imported certificate with ValidationException, each with its exact message, and leaves the
    certificate's status and serial unchanged."""
    acm = ctx.client("acm")
    arn, _cert_pem = _import_certificate(ctx, _domain(ctx))

    detail = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    eligibility = detail["RenewalEligibility"]
    assert eligibility == "INELIGIBLE", f"expected INELIGIBLE for an imported cert, got {eligibility}"

    # boundary 1: well-formed ARN, certificate does not exist
    fake_arn = _fake_certificate_arn(ctx)
    code_missing, message_missing = _error(lambda: acm.renew_certificate(CertificateArn=fake_arn))
    assert code_missing == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_missing}"
    expected_missing = f"Could not find certificate {fake_arn}."
    assert message_missing == expected_missing, f"expected message {expected_missing!r}, got {message_missing!r}"

    # boundary 2: certificate exists but is not eligible for managed renewal
    code_ineligible, message_ineligible = _error(lambda: acm.renew_certificate(CertificateArn=arn))
    assert code_ineligible == "ValidationException", f"expected ValidationException, got {code_ineligible}"
    expected_ineligible = (
        f"Certificate ARN {arn} is for a public or imported certificate "
        "and not eligible for the Renew Certificate API"
    )
    assert message_ineligible == expected_ineligible, (
        f"expected message {expected_ineligible!r}, got {message_ineligible!r}"
    )

    # confirm renewal was not attempted: certificate is unchanged
    still = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert still["Status"] == "ISSUED", f"expected ISSUED to be unchanged, got {still['Status']}"
    assert still["Serial"] == detail["Serial"], (
        f"expected Serial unchanged at {detail['Serial']!r} after rejected renewal, got {still['Serial']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _domain(ctx) -> str:
    return f"{ctx.unique_name('sim2real-acm-')}.example.com".lower()


def _fake_certificate_arn(ctx) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:acm:{ctx.region}:{account_id}:certificate/00000000-0000-0000-0000-000000000000"


def _generate_self_signed_cert(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _import_certificate(ctx, common_name: str):
    cert_pem, key_pem = _generate_self_signed_cert(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))
    return arn, cert_pem


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
