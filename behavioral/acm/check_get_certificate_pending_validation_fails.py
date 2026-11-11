"""get-certificate-pending-validation-fails."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-certificate-pending-validation-fails"
GROUP = 'overly-permissive'
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

def _request_cert(ctx, acm, domain=None, **kwargs):
    """Request a new AMAZON_ISSUED certificate. Returns (arn, domain)."""
    # A random ".com" name, not an RFC 2606 reserved one: ACM drives a reserved-domain request to
    # FAILED within seconds, while this one stays PENDING_VALIDATION for its 72-hour window.
    domain = domain or ctx.unique_name("sim2real-behav-req-").rstrip("-") + ".com"
    resp = _retry_throttle(lambda: acm.request_certificate(DomainName=domain, **kwargs))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, domain

def _self_signed_cert(common_name):
    """Generate a self-signed cert/key pair for ImportCertificate. Returns (cert_pem, key_pem)."""
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

def _import_cert(ctx, acm, domain=None):
    """Import a self-signed (already-ISSUED) certificate. Returns (arn, cert_pem)."""
    domain = domain or ctx.unique_name("sim2real-behav-imp-").rstrip("-") + ".example.com"
    cert_pem, key_pem = _self_signed_cert(domain)
    resp = _retry_throttle(lambda: acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, cert_pem

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCertificate on a PENDING_VALIDATION certificate is refused with RequestInProgressException
    and the exact message, while an imported certificate's bytes are returned as uploaded."""
    acm = ctx.client("acm")

    issued_arn, issued_pem = _import_cert(ctx, acm)
    positive = acm.get_certificate(CertificateArn=issued_arn)["Certificate"]
    if isinstance(positive, bytes):
        positive = positive.decode("ascii")
    assert positive.strip() == issued_pem.decode("ascii").strip(), (
        "positive control failed: GetCertificate on an ISSUED certificate did not "
        "return the imported bytes"
    )

    arn, _domain = _request_cert(ctx, acm)
    status = acm.describe_certificate(CertificateArn=arn)["Certificate"]["Status"]
    assert status == "PENDING_VALIDATION", f"expected PENDING_VALIDATION, got {status}"

    code, message = _error(lambda: acm.get_certificate(CertificateArn=arn))
    assert code == "RequestInProgressException", (
        f"expected RequestInProgressException on a PENDING_VALIDATION cert, got {code}"
    )
    expected_message = f"Certificate {arn} in account {arn.split(':')[4]} not yet issued"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
