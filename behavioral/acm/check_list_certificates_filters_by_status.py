"""list-certificates-filters-by-status."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "list-certificates-filters-by-status"
GROUP = "listing"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCertificates(CertificateStatuses=[...]) includes only certificates in that exact status."""
    import cryptography  # noqa: F401

    acm = ctx.client("acm")

    issued_domain = _domain(ctx, "listissued")
    cert_pem, key_pem, _key = _generate_self_signed_cert(issued_domain)
    issued_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, issued_arn))

    pending_domain = _domain(ctx, "listpending")
    pending_arn = acm.request_certificate(
        DomainName=pending_domain, ValidationMethod="DNS", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, pending_arn))
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=pending_arn)["Certificate"],
        lambda d: d["Status"] == "PENDING_VALIDATION",
        timeout_s=30.0,
    )

    issued_arns = _poll_until(
        lambda: _collect_arns(acm, ["ISSUED"]),
        lambda arns: issued_arn in arns,
        timeout_s=30.0,
    )
    # ListCertificates' status index is itself eventually consistent, independent of
    # DescribeCertificate already reporting PENDING_VALIDATION above.
    pending_arns = _poll_until(
        lambda: _collect_arns(acm, ["PENDING_VALIDATION"]),
        lambda arns: pending_arn in arns,
        timeout_s=120.0,
    )

    assert issued_arn in issued_arns, "ISSUED filter must include the imported (ISSUED) certificate"
    assert issued_arn not in pending_arns, "PENDING_VALIDATION filter must exclude the ISSUED certificate"
    assert pending_arn in pending_arns, "PENDING_VALIDATION filter must include the pending certificate"
    assert pending_arn not in issued_arns, "ISSUED filter must exclude the still-pending certificate"


# A random ".com" name, not an RFC 2606 reserved one: ACM drives a reserved-domain request to
# FAILED within seconds, while this one stays PENDING_VALIDATION for its 72-hour window.
def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    return f"{label}.com"


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


def _collect_arns(acm, statuses, max_pages: int = 20) -> set[str]:
    arns: set[str] = set()
    token = None
    for _ in range(max_pages):
        kwargs = {"CertificateStatuses": statuses, "MaxItems": 1000}
        if token:
            kwargs["NextToken"] = token
        resp = acm.list_certificates(**kwargs)
        arns.update(s["CertificateArn"] for s in resp.get("CertificateSummaryList", []))
        token = resp.get("NextToken")
        if not token:
            break
    return arns


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
