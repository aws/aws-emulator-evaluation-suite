"""list-certificates-pagination-consistent-with-describe."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "list-certificates-pagination-consistent-with-describe"
GROUP = "data-plane"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCertificates walked with MaxItems=2 pages at most two summaries per page and surfaces
    each imported certificate exactly once, with the DomainName DescribeCertificate returns.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    acm = ctx.client("acm")
    known: dict[str, str] = {}
    for i in range(3):
        domain = f"{ctx.unique_name('sim2real-acmls-').lower()}-{i}.test"
        cert_arn = _import_self_signed(ctx, acm, domain, x509, hashes, serialization, rsa, NameOID)
        known[cert_arn] = domain

    # ListCertificates is eventually consistent with respect to a just-completed ImportCertificate:
    # an immediate walk can miss a freshly imported cert entirely. Wait for all three to be visible
    # before asserting anything about the shape of the pagination, so a propagation delay is never
    # mistaken for a pagination or cursor defect.
    deadline = time.monotonic() + 60
    visible: set[str] = set()
    while time.monotonic() < deadline:
        visible = {
            c["CertificateArn"]
            for page in acm.get_paginator("list_certificates").paginate()
            for c in page["CertificateSummaryList"]
        }
        if set(known) <= visible:
            break
        time.sleep(3)
    else:
        assert False, (
            f"ListCertificates never surfaced all imported certs within 60s: "
            f"missing {set(known) - visible}"
        )

    seen: dict[str, str] = {}
    counts: dict[str, int] = {}
    token = None
    pages = 0
    for _ in range(500):
        kwargs = {"MaxItems": 2}
        if token:
            kwargs["NextToken"] = token
        page = acm.list_certificates(**kwargs)
        pages += 1
        size = len(page["CertificateSummaryList"])
        assert size <= 2, f"ListCertificates page {pages} holds {size} summaries over MaxItems=2"
        for summary in page["CertificateSummaryList"]:
            arn = summary["CertificateArn"]
            counts[arn] = counts.get(arn, 0) + 1
            assert arn not in seen or seen[arn] == summary.get("DomainName"), (
                f"duplicate ARN {arn} returned with inconsistent DomainName across pages"
            )
            seen[arn] = summary.get("DomainName")
        token = page.get("NextToken")
        if not token or all(arn in seen for arn in known):
            break

    assert pages >= 2, f"three certs surfaced in {pages} page(s) of MaxItems=2"
    missing = set(known) - set(seen)
    assert not missing, f"ListCertificates pagination never surfaced certs we created: {missing}"
    duplicated = {arn: counts[arn] for arn in known if counts[arn] != 1}
    assert not duplicated, (
        f"ListCertificates pagination returned a created cert more than once: {duplicated}"
    )

    for arn, domain in known.items():
        described = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        assert described["DomainName"] == domain
        assert described["CertificateArn"] == arn
        assert seen[arn] == domain, (
            f"ListCertificates summary DomainName mismatched DescribeCertificate for {arn}"
        )


def _import_self_signed(ctx, acm, domain, x509, hashes, serialization, rsa, NameOID):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    return cert_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
