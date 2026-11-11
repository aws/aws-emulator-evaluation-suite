"""reimport-certificate-different-domain-replaces-identity."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "reimport-certificate-different-domain-replaces-identity"
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
            Tags=[{"Key": "sim2real", "Value": CHECK}],
            **kwargs,
        )
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, cert_pem, key_pem

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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-importing a cert for a different domain onto an existing ARN keeps the ARN and replaces
    its identity: DescribeCertificate reports the new domain and GetCertificate the new body."""
    acm = ctx.client("acm")
    domain_a = ctx.unique_name("sim2real-behav-orig-").rstrip("-") + ".example.com"
    arn, cert_pem_a, _key_pem_a = _import_cert(ctx, acm, domain=domain_a)

    domain_b = ctx.unique_name("sim2real-behav-other-").rstrip("-") + ".example.com"
    cert_pem_b, key_pem_b = _self_signed_cert(domain_b)

    resp = _retry_throttle(
        lambda: acm.import_certificate(
            CertificateArn=arn, Certificate=cert_pem_b, PrivateKey=key_pem_b
        )
    )
    assert resp["CertificateArn"] == arn, f"re-import must preserve the ARN: expected {arn}, got {resp['CertificateArn']}"

    desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d["DomainName"] == domain_b,
        timeout_s=60,
        interval_s=3,
        description="re-imported certificate identity switched to the new domain",
    )
    assert desc["Status"] == "ISSUED", f"expected Status ISSUED after re-import, got {desc['Status']!r}"
    assert desc["Type"] == "IMPORTED", f"expected Type IMPORTED after re-import, got {desc['Type']!r}"

    got = acm.get_certificate(CertificateArn=arn)["Certificate"]
    if isinstance(got, bytes):
        got = got.decode("utf-8")
    expected_b = cert_pem_b.decode("utf-8").strip()
    stale_a = cert_pem_a.decode("utf-8").strip()
    assert got.strip() == expected_b, "GetCertificate must return the re-imported (domain_b) body, not the original"
    assert got.strip() != stale_a, "GetCertificate must not still return the stale domain_a body"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
