"""op-contract-revoke-certificate."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "op-contract-revoke-certificate"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RevokeCertificate refuses a nonexistent ARN with ResourceNotFoundException and an ISSUED
    imported certificate with ValidationException ("not a public certificate"), each with its exact
    message, and the imported certificate stays ISSUED without RevokedAt."""
    acm = ctx.client("acm")
    arn, _cert_pem = _import_certificate(ctx, _domain(ctx))

    # boundary 1: well-formed ARN, certificate does not exist
    fake_arn = _fake_certificate_arn(ctx)
    code_missing, message_missing = _client_error(
        lambda: acm.revoke_certificate(CertificateArn=fake_arn, RevocationReason="UNSPECIFIED")
    )
    assert code_missing == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_missing}"
    expected_missing = f"Could not find certificate {fake_arn}."
    assert message_missing == expected_missing, f"expected {expected_missing!r}, got {message_missing!r}"

    # boundary 2: certificate exists and is ISSUED, but is an imported
    # certificate (never exported, and not the private-CA-issued kind that
    # RevokeCertificate/ExportCertificate operate on)
    code_conflict, message_conflict = _client_error(
        lambda: acm.revoke_certificate(CertificateArn=arn, RevocationReason="UNSPECIFIED")
    )
    assert code_conflict == "ValidationException", f"expected ValidationException, got {code_conflict}"
    expected_conflict = f"Certificate {arn} is not a public certificate."
    assert message_conflict == expected_conflict, f"expected {expected_conflict!r}, got {message_conflict!r}"

    # the forbidden effect did not happen: the certificate is still ISSUED, not REVOKED
    still = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert still["Status"] == "ISSUED", f"expected ISSUED, got {still['Status']}"
    assert "RevokedAt" not in still, f"revoke must not have partially applied, got RevokedAt={still.get('RevokedAt')}"


def _client_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded and returned {result!r}")


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
