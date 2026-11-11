"""list-certificates-reflects-created."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "list-certificates-reflects-created"
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

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")

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
            Certificate=cert_pem, PrivateKey=key_pem,
            Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
        )
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, cert_pem, key_pem

def _request_cert(ctx, acm, domain=None, **kwargs):
    """Request a new AMAZON_ISSUED certificate. Returns (arn, domain)."""
    domain = domain or ctx.unique_name("sim2real-behav-req-").rstrip("-") + ".example.com"
    resp = _retry_throttle(lambda: acm.request_certificate(
        DomainName=domain, Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    ))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, domain

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCertificates includes both a requested and an imported certificate ARN."""
    acm = ctx.client("acm")
    req_arn, _domain = _request_cert(ctx, acm)
    imp_arn, _cert_pem, _key_pem = _import_cert(ctx, acm)

    def _list_all():
        arns = set()
        paginator = acm.get_paginator("list_certificates")
        for page in paginator.paginate():
            for c in page["CertificateSummaryList"]:
                arns.add(c["CertificateArn"])
        return arns

    all_arns = _poll_until(
        _list_all,
        lambda arns: req_arn in arns and imp_arn in arns,
        timeout_s=30,
        interval_s=2,
    )
    assert req_arn in all_arns, f"expected requested cert {req_arn} in ListCertificates, got {all_arns!r}"
    assert imp_arn in all_arns, f"expected imported cert {imp_arn} in ListCertificates, got {all_arns!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
