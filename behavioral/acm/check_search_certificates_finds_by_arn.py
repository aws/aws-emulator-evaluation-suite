"""search-certificates-finds-by-arn."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "search-certificates-finds-by-arn"
GROUP = "listing"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchCertificates with a CertificateArn filter returns exactly that one certificate."""
    import cryptography  # noqa: F401

    acm = ctx.client("acm")
    domain = _domain(ctx, "search")
    cert_pem, key_pem, _key = _generate_self_signed_cert(domain)
    arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    # SearchCertificates is backed by an index that can lag slightly behind ImportCertificate, so poll
    # for the newly imported certificate to become visible rather than assuming instant consistency.
    results = _poll_until(
        lambda: acm.search_certificates(FilterStatement={"Filter": {"CertificateArn": arn}})["Results"],
        lambda r: len(r) == 1,
        timeout_s=60.0,
    )
    assert len(results) == 1, results
    assert results[0]["CertificateArn"] == arn, (results[0], arn)
    # SearchCertificates results are CertificateSearchResult objects (CertificateArn + X509Attributes +
    # CertificateMetadata) -- unlike ListCertificates/DescribeCertificate summaries, there is no
    # top-level "DomainName" field here. The certificate's domain is instead exposed somewhere within
    # its X.509 attributes (subject / subject alternative names), so look for it there instead of
    # assuming a specific nested key name.
    assert _contains_value(results[0].get("X509Attributes", {}), domain), results[0]

    other_domain = _domain(ctx, "search-other")
    other_cert_pem, other_key_pem, _ = _generate_self_signed_cert(other_domain)
    other_arn = acm.import_certificate(
        Certificate=other_cert_pem, PrivateKey=other_key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, other_arn))
    resp2 = acm.search_certificates(FilterStatement={"Filter": {"CertificateArn": arn}})
    assert [r["CertificateArn"] for r in resp2["Results"]] == [arn], (
        "filtering by ARN must not return an unrelated certificate"
    )


def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    return f"{label}.example.com"


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


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _contains_value(obj, target: str) -> bool:
    if isinstance(obj, dict):
        return any(_contains_value(v, target) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_contains_value(v, target) for v in obj)
    return obj == target or (isinstance(obj, str) and target in obj)


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
