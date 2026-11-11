"""search-certificates-filters-by-status-server-side."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "search-certificates-filters-by-status-server-side"
GROUP = "server-side"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchCertificates applies Status and KeyAlgorithm filters server-side: scoped to two pending
    certs differing by key algorithm, each algorithm filter returns one, PENDING_VALIDATION
    matches both and ISSUED matches neither."""
    acm = ctx.client("acm")

    domain_rsa = f"{ctx.unique_name('sim2real-acm-rsa-')}.com".replace("_", "-")
    domain_ec = f"{ctx.unique_name('sim2real-acm-ec-')}.com".replace("_", "-")

    arn_rsa = acm.request_certificate(
        DomainName=domain_rsa, ValidationMethod="DNS", KeyAlgorithm="RSA_2048"
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn_rsa))

    arn_ec = acm.request_certificate(
        DomainName=domain_ec, ValidationMethod="DNS", KeyAlgorithm="EC_prime256v1"
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn_ec))

    scope = {
        "Or": [
            {"Filter": {"CertificateArn": arn_rsa}},
            {"Filter": {"CertificateArn": arn_ec}},
        ]
    }

    # Both certs should become visible to SearchCertificates promptly; poll.
    both = _poll_until(
        lambda: _search(acm, scope),
        lambda results: len(results) == 2,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert {r["CertificateArn"] for r in both} == {arn_rsa, arn_ec}

    # Filter narrowed to EC_prime256v1 key algorithm -> only the EC cert.
    ec_only = _search(
        acm,
        {"And": [scope, {"Filter": {"X509AttributeFilter": {"KeyAlgorithm": "EC_prime256v1"}}}]},
    )
    assert len(ec_only) == 1, f"expected exactly 1 EC_prime256v1 match, got {len(ec_only)}"
    assert ec_only[0]["CertificateArn"] == arn_ec
    assert ec_only[0]["X509Attributes"]["KeyAlgorithm"] == "EC_prime256v1"

    # Filter narrowed to RSA_2048 key algorithm -> only the RSA cert.
    rsa_only = _search(
        acm,
        {"And": [scope, {"Filter": {"X509AttributeFilter": {"KeyAlgorithm": "RSA_2048"}}}]},
    )
    assert len(rsa_only) == 1, f"expected exactly 1 RSA_2048 match, got {len(rsa_only)}"
    assert rsa_only[0]["CertificateArn"] == arn_rsa
    assert rsa_only[0]["X509Attributes"]["KeyAlgorithm"] == "RSA_2048"

    # Both certs are freshly requested -> both match Status=PENDING_VALIDATION.
    pending = _search(
        acm,
        {"And": [scope, {"Filter": {"AcmCertificateMetadataFilter": {"Status": "PENDING_VALIDATION"}}}]},
    )
    assert {r["CertificateArn"] for r in pending} == {arn_rsa, arn_ec}
    for r in pending:
        assert r["CertificateMetadata"]["AcmCertificateMetadata"]["Status"] == "PENDING_VALIDATION"

    # Neither cert is ISSUED yet -> Status=ISSUED filter excludes both.
    issued = _search(
        acm,
        {"And": [scope, {"Filter": {"AcmCertificateMetadataFilter": {"Status": "ISSUED"}}}]},
    )
    assert issued == [], f"expected no ISSUED matches among pending certs, got {issued}"


def _search(acm: Any, filter_statement: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"FilterStatement": filter_statement, "MaxResults": 50}
        if token:
            kwargs["NextToken"] = token
        resp = acm.search_certificates(**kwargs)
        results.extend(resp.get("Results", []))
        token = resp.get("NextToken")
        if not token:
            return results


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
