"""resend-validation-email-state-gated."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "resend-validation-email-state-gated"
GROUP = 'error-semantics'
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
    tags_kwarg = kwargs.pop(
        "Tags", [{"Key": "sim2real-purpose", "Value": "resend-validation-email-state-gated"}]
    )
    resp = _retry_throttle(
        lambda: acm.import_certificate(
            Certificate=cert_pem, PrivateKey=key_pem, Tags=tags_kwarg, **kwargs
        )
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, cert_pem, key_pem

def _retry_transient_state(fn, attempts=15, delay=6.0):
    """Bounded retry for ResendValidationEmail's transient InvalidStateException while ACM
    finishes asynchronously dispatching a just-requested certificate's initial validation
    email; this window clears well under a minute, but is not instantaneous."""
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidStateException":
                raise
            last = exc
            time.sleep(delay)
    raise last

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResendValidationEmail is gated on PENDING_VALIDATION: an ISSUED imported cert is rejected,
    while the same call succeeds on a PENDING_VALIDATION certificate under EMAIL validation."""
    acm = ctx.client("acm")
    domain = ctx.unique_name("sim2real-behav-resend-").rstrip("-") + ".example.com"
    arn, _cert_pem, _key_pem = _import_cert(ctx, acm, domain=domain)

    desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc["Status"] == "ISSUED", desc["Status"]
    assert desc["Type"] == "IMPORTED", desc["Type"]

    # The certificate's own domain is passed so a domain mismatch cannot cause the rejection.
    try:
        acm.resend_validation_email(
            CertificateArn=arn,
            Domain=domain,
            ValidationDomain=domain,
        )
        raise AssertionError("ResendValidationEmail must be rejected for an ISSUED/IMPORTED certificate")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidStateException", code
    expected = f"Certificate {arn} is not in pending validation state"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # The rejected call must not have mutated the certificate.
    still = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert still["Status"] == "ISSUED", still["Status"]

    # Positive control. Not ".example.com": ACM drives EMAIL validation for RFC 2606 reserved
    # domains to a terminal state within a minute, so resend is always rejected. A random
    # ".com" domain stays PENDING_VALIDATION (ACM times it out after 72 hours).
    pending_domain = f"{ctx.unique_name('sim2real-behav-resend-pend-')}.com"
    pending_resp = _retry_throttle(
        lambda: acm.request_certificate(
            DomainName=pending_domain,
            ValidationMethod="EMAIL",
            Tags=[{"Key": "sim2real-purpose", "Value": "resend-validation-email-state-gated"}],
        )
    )
    pending_arn = pending_resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=pending_arn), attempts=4, base_delay=3.0
        )
    )

    pending = acm.describe_certificate(CertificateArn=pending_arn)["Certificate"]
    assert pending["Status"] == "PENDING_VALIDATION", pending["Status"]

    # EMAIL-validation setup settles asynchronously; until then resend transiently raises
    # InvalidStateException ("still in progress") even though the certificate is eligible.
    response = _retry_transient_state(
        lambda: acm.resend_validation_email(
            CertificateArn=pending_arn, Domain=pending_domain, ValidationDomain=pending_domain
        )
    )
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200, response["ResponseMetadata"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
