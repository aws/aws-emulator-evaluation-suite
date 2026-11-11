"""renew-certificate-ineligible-fails."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "renew-certificate-ineligible-fails"
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
    tags_kw = kwargs.pop("Tags", [{"Key": "sim2real", "Value": CHECK}])
    resp = _retry_throttle(
        lambda: acm.import_certificate(
            Certificate=cert_pem, PrivateKey=key_pem, Tags=tags_kw, **kwargs
        )
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, cert_pem, key_pem

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RenewCertificate must reject a certificate that is not renewal-eligible."""
    acm = ctx.client("acm")
    arn, _cert_pem, _key_pem = _import_cert(ctx, acm)

    before = _retry_throttle(lambda: acm.describe_certificate(CertificateArn=arn))["Certificate"]
    assert before.get("RenewalEligibility") == "INELIGIBLE", (
        f"expected an imported certificate to report RenewalEligibility=INELIGIBLE, "
        f"got {before.get('RenewalEligibility')!r}"
    )
    serial_before = before["Serial"]
    status_before = before["Status"]

    try:
        result = acm.renew_certificate(CertificateArn=arn)
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"RenewCertificate on an ineligible certificate must be rejected, got {result!r}")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        f"Certificate ARN {arn} is for a public or imported certificate "
        "and not eligible for the Renew Certificate API"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = _retry_throttle(lambda: acm.describe_certificate(CertificateArn=arn))["Certificate"]
    assert after["Status"] == status_before, (
        f"status must not advance on a rejected renewal: was {status_before!r}, now {after['Status']!r}"
    )
    assert after["Serial"] == serial_before, (
        f"serial must not change on a rejected renewal: was {serial_before!r}, now {after['Serial']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
