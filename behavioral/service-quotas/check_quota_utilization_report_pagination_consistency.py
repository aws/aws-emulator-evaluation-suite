"""quota-utilization-report-pagination-consistency."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "quota-utilization-report-pagination-consistency"
GROUP = "state-machine"
SERVICES = ["service-quotas"]

_REQUIRED_FIELDS = (
    "ServiceCode",
    "QuotaCode",
    "QuotaName",
    "ServiceName",
    "Utilization",
    "Adjustable",
)


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paging a completed quota utilization report with MaxResults=5 terminates, keeps every page
    COMPLETED with TotalCount equal to its own item count, and yields exactly the duplicate-free
    record set of one unpaginated read, every record carrying its documented fields."""
    sq = ctx.client("service-quotas")
    report_id = sq.start_quota_utilization_report()["ReportId"]

    deadline = time.monotonic() + 120.0
    completed = None
    while time.monotonic() < deadline:
        resp = sq.get_quota_utilization_report(ReportId=report_id)
        if resp["Status"] in {"COMPLETED", "FAILED"}:
            completed = resp
            break
        time.sleep(3.0)
    assert completed is not None and completed["Status"] == "COMPLETED", "report did not complete in time"

    # Independent side-channel: an unpaginated read (no MaxResults) of the same
    # completed report is the reference set the paginated walk below must
    # reproduce exactly. On real AWS this fits in one page, so a NextToken here
    # would mean the reference itself needs paging and can no longer serve as
    # ground truth.
    assert not completed.get("NextToken"), (
        "unpaginated GetQuotaUtilizationReport unexpectedly returned a NextToken; "
        "the reference read must be a single page to be trustworthy"
    )
    for item in completed["Quotas"]:
        for field in _REQUIRED_FIELDS:
            assert field in item, f"quota utilization record missing {field!r}: {item}"
    reference_pairs = {(q["ServiceCode"], q["QuotaCode"]) for q in completed["Quotas"]}
    assert len(reference_pairs) == len(completed["Quotas"]), (
        "the unpaginated reference read itself contains duplicate (ServiceCode, QuotaCode) records"
    )

    token = None
    pages_seen = 0
    seen_pairs: list[tuple] = []
    for _ in range(2000):
        page = (
            sq.get_quota_utilization_report(ReportId=report_id, MaxResults=5, NextToken=token)
            if token
            else sq.get_quota_utilization_report(ReportId=report_id, MaxResults=5)
        )
        pages_seen += 1
        assert page["Status"] == "COMPLETED", f"page {pages_seen} status regressed to {page['Status']!r}"
        assert page["ReportId"] == report_id, (
            f"page {pages_seen} ReportId {page['ReportId']!r} != {report_id!r}"
        )
        assert len(page["Quotas"]) <= 5, "a page exceeded the requested MaxResults"
        # Real AWS's paginated TotalCount is NOT the grand total across all pages
        # despite the field's documentation -- it mirrors this page's own item
        # count, including on a truncated final page.
        assert page["TotalCount"] == len(page["Quotas"]), (
            "a paginated page's TotalCount diverged from its own item count "
            f"(real AWS's observed contract): TotalCount={page['TotalCount']} "
            f"but page {pages_seen} carries {len(page['Quotas'])} records"
        )
        for item in page["Quotas"]:
            for field in _REQUIRED_FIELDS:
                assert field in item, f"quota utilization record missing {field!r}: {item}"
            seen_pairs.append((item["ServiceCode"], item["QuotaCode"]))
        token = page.get("NextToken")
        if not token:
            break
        assert pages_seen < 2000, "report pagination did not terminate within 2000 pages"
    else:
        if token:
            raise AssertionError("report pagination did not terminate within 2000 pages")

    assert len(seen_pairs) == len(set(seen_pairs)), (
        "pagination returned a duplicate (ServiceCode, QuotaCode) record across pages"
    )
    assert set(seen_pairs) == reference_pairs, (
        "paginated walk's record set diverges from the same report's independent "
        f"unpaginated read: missing={reference_pairs - set(seen_pairs)!r} "
        f"extra={set(seen_pairs) - reference_pairs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
