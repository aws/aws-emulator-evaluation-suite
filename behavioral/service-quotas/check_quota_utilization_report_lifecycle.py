"""quota-utilization-report-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "quota-utilization-report-lifecycle"
GROUP = "state-machine"
SERVICES = ["service-quotas"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartQuotaUtilizationReport's report reaches COMPLETED through GetQuotaUtilizationReport with
    its ReportId, a GeneratedAt, a Quotas list and a TotalCount of at least the listed items."""
    sq = ctx.client("service-quotas")
    started = sq.start_quota_utilization_report()
    report_id = started["ReportId"]
    assert started["Status"] in {"PENDING", "IN_PROGRESS", "COMPLETED"}, (
        f"unexpected initial status for a freshly started report: {started['Status']!r}"
    )

    deadline = time.monotonic() + 120.0
    final = None
    while time.monotonic() < deadline:
        final = sq.get_quota_utilization_report(ReportId=report_id)
        if final["Status"] in {"COMPLETED", "FAILED"}:
            break
        time.sleep(3.0)
    assert final is not None, f"never received a response polling report {report_id}"
    assert final["Status"] == "COMPLETED", (
        f"report {report_id} did not complete within 120s (status={final['Status']!r}, "
        f"error={final.get('ErrorCode')}/{final.get('ErrorMessage')})"
    )
    assert final["ReportId"] == report_id, (
        f"GetQuotaUtilizationReport returned ReportId {final['ReportId']!r}, expected {report_id!r}"
    )
    assert "GeneratedAt" in final, f"completed report is missing GeneratedAt: {final}"
    assert final["TotalCount"] >= 0, f"TotalCount must be non-negative, got {final['TotalCount']!r}"
    assert isinstance(final["Quotas"], list), f"Quotas must be a list, got {type(final['Quotas'])!r}"
    assert final["TotalCount"] >= len(final["Quotas"]), (
        f"TotalCount {final['TotalCount']!r} is smaller than the returned page of "
        f"{len(final['Quotas'])} Quotas records"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
