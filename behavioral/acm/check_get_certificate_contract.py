"""op-contract-get-certificate."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "op-contract-get-certificate"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCertificate on an ISSUED imported certificate returns the exact PEM bytes
    that were imported; GetCertificate on a certificate still in PENDING_VALIDATION
    is rejected with RequestInProgressException."""
    acm = ctx.client("acm")
    arn, cert_pem = _import_certificate(ctx, _domain(ctx))

    got = acm.get_certificate(CertificateArn=arn)
    assert got["Certificate"].encode("ascii") == cert_pem, "returned certificate body is not byte-identical"

    # error boundary: a freshly requested certificate for a domain we don't control
    # DNS for stays PENDING_VALIDATION indefinitely, so GetCertificate must refuse
    pending_domain = _domain(ctx)
    pending_arn = acm.request_certificate(
        DomainName=pending_domain,
        ValidationMethod="DNS",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=pending_arn))

    status = acm.describe_certificate(CertificateArn=pending_arn)["Certificate"]["Status"]
    assert status == "PENDING_VALIDATION", f"unexpected initial status {status}"

    code, message = _error(lambda: acm.get_certificate(CertificateArn=pending_arn))
    assert code == "RequestInProgressException", f"expected RequestInProgressException, got {code}"
    account = pending_arn.split(":")[4]
    expected_message = f"Certificate {pending_arn} in account {account} not yet issued"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


# A random ".com" name, not an RFC 2606 reserved one: ACM drives a reserved-domain request to
# FAILED within seconds, while this one stays PENDING_VALIDATION for its 72-hour window.
def _domain(ctx) -> str:
    return f"{ctx.unique_name('sim2real-acm-')}.com".lower()


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
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))
    return arn, cert_pem


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
