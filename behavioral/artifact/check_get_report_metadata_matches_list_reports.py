"""get-report-metadata-matches-list-reports."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-report-metadata-matches-list-reports"
GROUP = "data-plane"
SERVICES = ["artifact"]

# Fields the ReportSummary and ReportDetail shapes both model (per the artifact
# Smithy model) -- everything GetReportMetadata could echo back inconsistently
# with what ListReports already showed the caller.
_SHARED_OPTIONAL_FIELDS = (
    "uploadState",
    "acceptanceType",
    "description",
    "category",
    "series",
    "companyName",
    "productName",
    "statusMessage",
    "periodStart",
    "periodEnd",
)


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetReportMetadata for a report returned by ListReports reports back the same
    identity fields (id, arn, name, version, state) -- and every other field the two
    shapes both model -- as the catalog listing."""
    art = ctx.client("artifact")
    listed = art.list_reports(maxResults=1)["reports"]
    assert len(listed) == 1, f"expected exactly 1 report from list_reports(maxResults=1), got {len(listed)}"
    summary = listed[0]

    detail = art.get_report_metadata(reportId=summary["id"])["reportDetails"]

    assert detail["id"] == summary["id"], f"id mismatch: detail={detail['id']!r} summary={summary['id']!r}"
    assert detail["arn"] == summary["arn"], f"arn mismatch: detail={detail['arn']!r} summary={summary['arn']!r}"
    assert detail["name"] == summary["name"], (
        f"name mismatch: detail={detail['name']!r} summary={summary['name']!r}"
    )
    assert detail["version"] == summary["version"], (
        f"version mismatch: detail={detail['version']!r} summary={summary['version']!r}"
    )
    assert detail["state"] == summary["state"], (
        f"state mismatch: detail={detail['state']!r} summary={summary['state']!r}"
    )
    assert detail["arn"].startswith("arn:"), f"malformed arn: {detail['arn']!r}"

    # ListReports is a thinner projection: real AWS omits some optional fields
    # (e.g. uploadState) from the summary even when GetReportMetadata populates
    # them, so absence from `summary` is not a divergence. Whatever the summary
    # DOES choose to expose must agree with the authoritative detail, though.
    for field in _SHARED_OPTIONAL_FIELDS:
        if field not in summary:
            continue
        assert summary[field] == detail.get(field), (
            f"{field} mismatch between ListReports summary and GetReportMetadata detail: "
            f"summary={summary[field]!r} detail={detail.get(field)!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
