"""search-certificates-reflects-server-side-index."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-certificates-reflects-server-side-index"
GROUP = "server-side"
SERVICES = ["acm"]

_ALL_STATUSES = [
    "PENDING_VALIDATION",
    "ISSUED",
    "INACTIVE",
    "EXPIRED",
    "VALIDATION_TIMED_OUT",
    "REVOKED",
    "FAILED",
]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A requested certificate appears in SearchCertificates and ListCertificates with Status/Type
    matching DescribeCertificate; after DeleteCertificate all three stop returning it."""
    acm = ctx.client("acm")
    domain = f"{ctx.unique_name('sim2real-acm-idx-')}.com".lower()

    cert_arn = acm.request_certificate(DomainName=domain, ValidationMethod="DNS")[
        "CertificateArn"
    ]
    ctx.on_cleanup(lambda: _safe_delete(acm, cert_arn))

    # A just-requested certificate can briefly describe without its DomainName; wait for it.
    deadline = time.monotonic() + 30
    described = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    while "DomainName" not in described and time.monotonic() < deadline:
        time.sleep(2)
        described = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    assert described.get("DomainName") == domain, (
        f"DescribeCertificate DomainName: expected {domain!r}, got {described.get('DomainName')!r}"
    )
    assert described["Status"] == "PENDING_VALIDATION", (
        f"DescribeCertificate Status: expected PENDING_VALIDATION, got {described['Status']!r}"
    )
    assert described["Type"] == "AMAZON_ISSUED", (
        f"DescribeCertificate Type: expected AMAZON_ISSUED, got {described['Type']!r}"
    )

    search_result, list_summary = _wait_for_indexed(ctx, cert_arn)

    # SearchCertificates' ACM metadata for this certificate agrees with DescribeCertificate.
    # CertificateMetadata is a union whose only current member is AcmCertificateMetadata --
    # the actual Status/Type/ValidationMethod fields live one level down inside it.
    search_meta = search_result["CertificateMetadata"]["AcmCertificateMetadata"]
    assert search_result["CertificateArn"] == cert_arn, (
        f"SearchCertificates CertificateArn: expected {cert_arn!r}, got "
        f"{search_result['CertificateArn']!r}"
    )
    assert search_meta["Status"] == described["Status"] == "PENDING_VALIDATION", (
        f"SearchCertificates Status {search_meta['Status']!r} vs DescribeCertificate Status "
        f"{described['Status']!r}, expected both PENDING_VALIDATION"
    )
    assert search_meta["Type"] == described["Type"] == "AMAZON_ISSUED", (
        f"SearchCertificates Type {search_meta['Type']!r} vs DescribeCertificate Type "
        f"{described['Type']!r}, expected both AMAZON_ISSUED"
    )
    assert search_meta["ValidationMethod"] == "DNS", (
        f"SearchCertificates ValidationMethod: expected DNS, got "
        f"{search_meta['ValidationMethod']!r}"
    )

    # ListCertificates' summary for the SAME certificate agrees with both of the above --
    # all three views are reads over one underlying server-side index.
    assert list_summary["CertificateArn"] == cert_arn, (
        f"ListCertificates CertificateArn: expected {cert_arn!r}, got "
        f"{list_summary['CertificateArn']!r}"
    )
    assert list_summary["DomainName"] == domain == described["DomainName"], (
        f"ListCertificates DomainName {list_summary['DomainName']!r} vs DescribeCertificate "
        f"DomainName {described['DomainName']!r}, expected both {domain!r}"
    )
    assert list_summary["Status"] == described["Status"], (
        f"ListCertificates Status {list_summary['Status']!r} != DescribeCertificate Status "
        f"{described['Status']!r}"
    )
    assert list_summary["Type"] == described["Type"], (
        f"ListCertificates Type {list_summary['Type']!r} != DescribeCertificate Type "
        f"{described['Type']!r}"
    )

    # The same server-side index retracts the certificate on delete: Describe, Search and
    # List all independently stop seeing it.
    acm.delete_certificate(CertificateArn=cert_arn)

    try:
        acm.describe_certificate(CertificateArn=cert_arn)
        raise AssertionError("DescribeCertificate after delete must be refused")
    except ClientError as exc:
        described_code = exc.response.get("Error", {}).get("Code")
        described_message = exc.response.get("Error", {}).get("Message")
    assert described_code == "ResourceNotFoundException", (
        f"DescribeCertificate after delete: expected ResourceNotFoundException, got "
        f"{described_code!r}"
    )
    expected_message = f"Could not find certificate {cert_arn}."
    assert described_message == expected_message, (
        f"DescribeCertificate after delete: expected {expected_message!r}, got {described_message!r}"
    )

    _wait_for_removed(ctx, cert_arn)


def _search_by_arn(acm, cert_arn):
    resp = acm.search_certificates(FilterStatement={"Filter": {"CertificateArn": cert_arn}})
    results = resp.get("Results", [])
    return results[0] if results else None


def _find_in_list_certificates(acm, cert_arn, statuses, max_pages=50, page_size=200):
    kwargs = {
        "CertificateStatuses": statuses,
        "MaxItems": page_size,
    }
    for _ in range(max_pages):
        resp = acm.list_certificates(**kwargs)
        for summary in resp.get("CertificateSummaryList", []):
            if summary["CertificateArn"] == cert_arn:
                return summary
        next_token = resp.get("NextToken")
        if not next_token:
            return None
        kwargs["NextToken"] = next_token
    return None


def _wait_for_indexed(ctx, cert_arn, timeout_s=90.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_search, last_list = None, None
    while time.monotonic() < deadline:
        last_search = _search_by_arn(acm, cert_arn)
        last_list = _find_in_list_certificates(acm, cert_arn, ["PENDING_VALIDATION"])
        if last_search is not None and last_list is not None:
            return last_search, last_list
        time.sleep(interval_s)
    raise AssertionError(
        f"certificate {cert_arn} not indexed within {timeout_s}s "
        f"(search_hit={last_search is not None}, list_hit={last_list is not None})"
    )


def _wait_for_removed(ctx, cert_arn, timeout_s=90.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_search, last_list = "unchecked", "unchecked"
    while time.monotonic() < deadline:
        last_search = _search_by_arn(acm, cert_arn)
        last_list = _find_in_list_certificates(acm, cert_arn, _ALL_STATUSES)
        if last_search is None and last_list is None:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"certificate {cert_arn} still indexed {timeout_s}s after DeleteCertificate "
        f"(search_hit={last_search is not None}, list_hit={last_list is not None})"
    )


def _safe_delete(acm, cert_arn):
    try:
        acm.delete_certificate(CertificateArn=cert_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
