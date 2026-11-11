"""delete-certificate-removes-resource."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "delete-certificate-removes-resource"
GROUP = 'lifecycle'
SERVICES = ['acm']

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)

def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes (test-infra robustness, not a behavioral assertion)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last

def _self_signed_cert(common_name, days_valid=365, key_size=2048, san_names=None):
    """Generate a self-signed cert/key pair for ImportCertificate. Returns (cert_pem, key_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    sans = san_names if san_names else [common_name]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem

def _import_cert(ctx, acm, domain=None, **kwargs):
    """Generate a self-signed cert and import it. Returns (arn, cert_pem, key_pem)."""
    domain = domain or ctx.unique_name("sim2real-behav-imported-").rstrip("-") + ".example.com"
    cert_pem, key_pem = _self_signed_cert(domain)
    resp = _retry_throttle(
        lambda: acm.import_certificate(
            Certificate=cert_pem,
            PrivateKey=key_pem,
            Tags=[{"Key": "sim2real-purpose", "Value": CHECK}],
            **kwargs,
        )
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_throttle(lambda: _delete_if_present(acm, arn), attempts=4, base_delay=3.0))
    return arn, cert_pem, key_pem

def _delete_if_present(acm, arn):
    """Teardown delete; a certificate the check already deleted reads ResourceNotFoundException."""
    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCertificate is a terminal removal: subsequent Describe -> ResourceNotFoundException,
    and a mutation against the now-dead ARN (AddTagsToCertificate) hits the same not-found boundary
    rather than silently succeeding against nothing."""
    acm = ctx.client("acm")
    arn, _cert_pem, _key_pem = _import_cert(ctx, acm)

    acm.delete_certificate(CertificateArn=arn)

    expected_message = f"Could not find certificate {arn}."
    code, message = _error_code(lambda: acm.describe_certificate(CertificateArn=arn))
    assert code == "ResourceNotFoundException", (code, message)
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    mutate_code, mutate_message = _error_code(
        lambda: acm.add_tags_to_certificate(
            CertificateArn=arn, Tags=[{"Key": "sim2real-post-delete-probe", "Value": "1"}]
        )
    )
    assert mutate_code == "ResourceNotFoundException", (mutate_code, mutate_message)
    assert mutate_message == expected_message, f"expected message {expected_message!r}, got {mutate_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
